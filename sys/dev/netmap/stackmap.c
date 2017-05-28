/*
 * Copyright (C) 2015 NetApp. Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * common headers
 */
#if defined(__FreeBSD__)
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>	/* defines used in kernel.h */
#include <sys/kernel.h>	/* types used in module initialization */
#include <sys/conf.h>	/* cdevsw struct, UID, GID */
#include <sys/sockio.h>
#include <sys/socketvar.h>	/* struct socket */
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/rwlock.h>
#include <sys/socket.h> /* sockaddrs */
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/bpf.h>		/* BIOCIMMEDIATE */
#include <machine/bus.h>	/* bus_dmamap_* */
#include <sys/endian.h>
#include <sys/refcount.h>

#elif defined(linux)
#include <bsd_glue.h>
#endif

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>
#include <dev/netmap/netmap_bdg.h>

#ifdef WITH_STACK
static int stackmap_no_runtocomp = 0;

int stackmap_verbose = 0;
static int stackmap_extra = 4;
SYSBEGIN(vars_stack);
SYSCTL_DECL(_dev_netmap);
SYSCTL_INT(_dev_netmap, OID_AUTO, stackmap_no_runtocomp, CTLFLAG_RW, &stackmap_no_runtocomp, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, stackmap_verbose, CTLFLAG_RW, &stackmap_verbose, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, stackmap_extra, CTLFLAG_RW, &stackmap_extra, 0 , "");
SYSEND;

static inline struct netmap_adapter *
stackmap_master(const struct netmap_adapter *slave)
{
	struct netmap_vp_adapter *vpna;

	if (!slave)
		return NULL;
	vpna = (struct netmap_vp_adapter *)slave;
	return &netmap_bdg_port(vpna->na_bdg, 0)->up;
}

static inline int
stackmap_is_host(struct netmap_adapter *na)
{
	return na->nm_register == NULL;
}

/* nm_notify() for NIC RX */
static int
stackmap_intr_notify(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na, *vpna, *mna;
	enum txrx t = NR_RX;

	na = kring->na;
	vpna = (struct netmap_adapter *)na->na_private;
	if (!vpna)
		return NM_IRQ_COMPLETED;

	/* maybe TX */
	if (kring >= NMR(na, NR_TX) &&
	    kring <= NMR(na, NR_TX) + na->num_tx_rings) {
		t = NR_TX;
	}

	/* just wakeup the client on the master */
	mna = stackmap_master(vpna);
	if (mna) {
		struct netmap_kring *mkring;
		u_int me = kring - NMR(na, t), mnr;

		if (stackmap_no_runtocomp)
			return netmap_bwrap_intr_notify(kring, flags);
		mnr = t == NR_RX ? mna->num_rx_rings : mna->num_tx_rings;
		mkring = &NMR(mna, t)[mnr > me ? me : 0];
		mkring->nm_notify(mkring, 0);
	}
	return NM_IRQ_COMPLETED;
}

/*
 * We need to form lists using scb and buf_idx, because they
 * can be very long due to ofo packets that have been queued
 */
#define STACKMAP_FT_SCB
#define STACKMAP_FD_HOST	(NM_BDG_MAXPORTS*NM_BDG_MAXRINGS-1)

#ifdef STACKMAP_FT_SCB
struct stackmap_bdg_q {
	uint32_t bq_head;
	uint32_t bq_tail;
};
#endif

struct stackmap_bdgfwd {
#ifdef STACKMAP_FT_SCB
	uint16_t nfds;
	uint16_t npkts;
	struct stackmap_bdg_q fde[NM_BDG_MAXPORTS * NM_BDG_MAXRINGS
	       	+ NM_BDG_BATCH_MAX]; /* XXX */
	uint32_t tmp[NM_BDG_BATCH_MAX];
#else
	struct nm_bdg_fwd ft[NM_BDG_BATCH_MAX]; /* 16 byte each */
	struct nm_bdg_q fde[NM_BDG_MAXPORTS * NM_BDG_MAXRINGS]; // 8 byte left
	uint16_t nfds;
	uint16_t npkts;
#endif
	uint32_t fds[NM_BDG_BATCH_MAX/2]; // max fd index
};
#ifdef STACKMAP_FT_SCB
#define STACKMAP_FT_NULL 0	// invalid buf index
#else
#define STACKMAP_FT_NULL NM_FT_NULL
#endif /* STACKMAP_FT_SCB */

/* TODO: avoid linear search... */
int
stackmap_extra_enqueue(struct netmap_kring *kring, struct netmap_slot *slot)
{
	struct netmap_adapter *na = kring->na;
	struct netmap_slot *slots = kring->extra->slots;
	int i, n = kring->extra->num;

	for (i = 0; i < n; i++) {
		struct netmap_slot *extra = &slots[i];
		struct netmap_slot tmp;
		struct stackmap_cb *xcb;

		xcb = STACKMAP_CB_NMB(NMB(na, extra), NETMAP_BUF_SIZE(na));
		if (stackmap_cb_valid(xcb) &&
		    stackmap_cb_get_state(xcb) != SCB_M_NOREF && extra->len) {
			continue;
		}

		scbw(xcb, NULL, extra);
		tmp = *extra;
		*extra = *slot;
		/* no need for NS_BUF_CHANGED on extra slot */
		if (!slot->buf_idx && !tmp.buf_idx) {
			panic("invalid (0) buf idx");
		}
		slot->buf_idx = tmp.buf_idx;
		slot->flags |= NS_BUF_CHANGED;
		slot->len = slot->offset = slot->next = 0;
		slot->fd = 0;
		return 0;
	}
	return EBUSY;
}

static inline struct stackmap_bdgfwd *
stackmap_get_bdg_fwd(struct netmap_kring *kring)
{
	return (struct stackmap_bdgfwd *)kring->nkr_ft;
}

void
stackmap_add_fdtable(struct stackmap_cb *scb, struct netmap_kring *kring)
{
	struct netmap_slot *slot = scb_slot(scb);
	struct stackmap_bdgfwd *ft;
	uint32_t fd = slot->fd;
#ifdef STACKMAP_FT_SCB
	struct stackmap_bdg_q *fde;
#else
	struct nm_bdg_fwd *ft_p;
	struct nm_bdg_q *fde;
#endif
	int i;

	ft = stackmap_get_bdg_fwd(kring);
#ifdef STACKMAP_FT_SCB
	i = slot->buf_idx;
	scb->next = STACKMAP_FT_NULL;
#else
	if (unlikely(ft->npkts > NM_BDG_BATCH_MAX)) {
		SD(SD_QUE, 0, "ft full");
		return;
	}
	i = ft->npkts;
	ft_p = ft->ft + i;
	ft_p->ft_next = STACKMAP_FT_NULL;
	ft_p->ft_slot = slot;
#endif
	fde = ft->fde + fd;
	if (fde->bq_head == STACKMAP_FT_NULL) {
		fde->bq_head = fde->bq_tail = i;
		ft->fds[ft->nfds++] = fd;
	} else {
#ifdef STACKMAP_FT_SCB
		struct netmap_slot s = { fde->bq_tail };
		struct stackmap_cb *prev = STACKMAP_CB_NMB(NMB(kring->na, &s),
				NETMAP_BUF_SIZE(kring->na));
		prev->next = fde->bq_tail = i;
#else
		ft->ft[fde->bq_tail].ft_next = i;
		fde->bq_tail = i;
#endif
	}
	ft->npkts++;
}

/* TX:
 * 1. sort packets by socket with forming send buffer (in-order iteration)
 * 2. do tcp processing on each socket (out-of-order iteration)
 * We must take into account MOREFRAGS.
 * We do not support INDIRECT as packet movement is done by swapping
 * We thus overwrite ptr field (8 byte width) in a slot to store a 
 * socket (4 byte), next buf index (2 byte).
 * The rest of 2 bytes may be used to store the number of frags 
 * (1 byte) and destination port (1 byte).
 */

static inline struct nm_bdg_q *
stackmap_fdtable(struct nm_bdg_fwd *ft)
{
	return (struct nm_bdg_q *)(ft + NM_BDG_BATCH_MAX);
}

struct stackmap_sk_adapter *
stackmap_ska_from_fd(struct netmap_adapter *na, int fd)
{
	struct stackmap_adapter *sna = (struct stackmap_adapter *)na;

	if (unlikely(fd >= sna->sk_adapters_max))
		return NULL;
	return sna->sk_adapters[fd];
}

/* Differ from nm_kr_space() due to different meaning of the lease */
static inline uint32_t
stackmap_kr_rxspace(struct netmap_kring *k)
{
	int space;
	int busy = k->nr_hwtail - k->nkr_hwlease;

	if (busy < 0)
		busy += k->nkr_num_slots;
	space = k->nkr_num_slots - 1 - busy;
	return space;
}

static int
stackmap_bdg_flush(struct netmap_kring *kring)
{
	int k = kring->nr_hwcur, j;
	const int rhead = kring->rhead;
	u_int lim_tx = kring->nkr_num_slots - 1;
	struct netmap_adapter *na = kring->na;
	struct netmap_vp_adapter *vpna =
		(struct netmap_vp_adapter *)na;
	struct netmap_adapter *rxna;
	struct stackmap_bdgfwd *ft;
	int32_t n, lim_rx, howmany;
	u_int dring;
	struct netmap_kring *rxkring;
	bool rx = 0, host = stackmap_is_host(na);
#ifdef STACKMAP_FT_SCB
	int leftover;
#endif
	u_int nonfree_num = 0;
	uint32_t *nonfree;

	ft = stackmap_get_bdg_fwd(kring);
#ifdef STACKMAP_FT_SCB
	leftover = ft->npkts;
	nonfree = ft->tmp;
#else
	ft->npkts = ft->nfds = 0;
#endif

	if (netmap_bdg_rlock(vpna->na_bdg, na)) {
		SD(SD_GEN, 1, "failed to obtain rlock");
		return k;
	}

	/* XXX perhaps this is handled later? */
	if (netmap_bdg_active_ports(vpna->na_bdg) < 3) {
		SD(SD_GEN, 1, "only 1 or 2 active ports");
		goto unlock_out;
	}

	/* let the host stack packets go earlier */

	if (na == stackmap_master(na) || host) {
		rxna = &netmap_bdg_port(vpna->na_bdg, 1)->up; /* XXX */
	} else {
		rxna = stackmap_master(na);
		local_bh_disable();
		rx = 1;
	}

	for (k = kring->nkr_hwlease; k != rhead; k = nm_next(k, lim_tx)) {
		struct netmap_slot *slot = &kring->ring->slot[k];
		struct stackmap_cb *scb;
		char *nmb = NMB(na, slot);
		int error;

		__builtin_prefetch(nmb);
		if (unlikely(slot->len == 0)) {
			continue;
		}
		scb = STACKMAP_CB_NMB(nmb, NETMAP_BUF_SIZE(na));
		if (host) {
			slot->fd = STACKMAP_FD_HOST;
			scbw(scb, kring, slot);
			stackmap_cb_set_state(scb, SCB_M_NOREF);
			stackmap_add_fdtable(scb, kring);
			SDPKT(SD_HOST, 0, nmb + na->virt_hdr_len);
			continue;
		}
		stackmap_cb_invalidate(scb);
		scbw(scb, kring, slot);
		error = rx ? nm_os_stackmap_recv(kring, slot) :
			     nm_os_stackmap_send(kring, slot);
		if (unlikely(error)) {
			/* Must be EBUSY (TX/RX) or EAGAIN (TX) */
			SD(SD_GEN, 1, "%s early break", rx ? "rx" : "tx");
			if (error == -EBUSY)
				k = nm_next(k, lim_tx);
			break;
		}
	}
	kring->nkr_hwlease = k; // next position to throw into the stack

	/* Now, we know how many packets go to the receiver
	 * On TX we can drop packets with handling packets with 
	 * references appropriately.
	 * On RX we cannot do so.
	 */

	if (unlikely(!nm_netmap_on(rxna))) {
		panic("receiver na off");
	}
	dring = kring - NMR(kring->na, NR_TX);
	nm_bound_var(&dring, 0, 0, rxna->num_rx_rings, NULL);
	rxkring = NMR(rxna, NR_RX) + dring;
	lim_rx = rxkring->nkr_num_slots - 1;
	j = rxkring->nr_hwtail;

	/* under lock */

	mtx_lock(&rxkring->q_lock);
	if (unlikely(rxkring->nkr_stopped)) {
		mtx_unlock(&rxkring->q_lock);
		goto unlock_out;
	}
	howmany = stackmap_kr_rxspace(rxkring); // we don't use lease
	if (howmany < ft->npkts) {
		/* Reclaim completed buffers */
		u_int i;

		for (i = rxkring->nkr_hwlease, n = 0; i != rxkring->nr_hwtail;
		     i = nm_next(i, lim_rx), n++) {
			struct netmap_slot *slot = &rxkring->ring->slot[i];
			struct stackmap_cb *scb;

			scb = STACKMAP_CB_NMB(NMB(rxna, slot),
					NETMAP_BUF_SIZE(rxna));
			if (stackmap_cb_valid(scb) &&
			    stackmap_cb_get_state(scb) != SCB_M_NOREF)
				break;
		}
		howmany += n;
		rxkring->nkr_hwlease = i;
	} else if (ft->npkts < howmany) {
		howmany = ft->npkts;
	}

	for (n = 0; n < ft->nfds; n++) {
#ifdef STACKMAP_FT_SCB
		struct stackmap_bdg_q *bq;
#else
		struct nm_bdg_q *bq;
#endif
		uint32_t fd, next, sent = 0;

		fd = ft->fds[n];
		bq = ft->fde + fd;
		next = bq->bq_head;
		do {
			struct netmap_slot tmp, *ts, *rs;
#ifdef STACKMAP_FT_SCB
			struct stackmap_cb *scb;

			tmp.buf_idx = next;
			scb = STACKMAP_CB_NMB(NMB(na, &tmp),
					      NETMAP_BUF_SIZE(na));
			next = scb->next;
			ts = scb_slot(scb);
#else /* !STACKMAP_FT_SCB */
			struct nm_bdg_fwd *ft_p = ft->ft + next;

			next = ft_p->ft_next;
			ts = ft_p->ft_slot;
#endif /* STACKMAP_FT_SCB */
			rs = &rxkring->ring->slot[j];
			if (stackmap_cb_get_state(scb) == SCB_M_TXREF) {
				nonfree[nonfree_num++] = j;
				scbw(scb, rxkring, rs);
			} else if (stackmap_cb_get_state(scb) == SCB_M_NOREF) {
				stackmap_cb_invalidate(scb);
			}
			tmp = *rs;
			*rs = *ts;
			*ts = tmp;
			ts->len = ts->offset = 0;
			ts->fd = 0;
			ts->flags |= NS_BUF_CHANGED;
			rs->flags |= NS_BUF_CHANGED;
			j = nm_next(j, lim_rx);
			sent++;
		} while (--howmany && next != STACKMAP_FT_NULL);
		bq->bq_head = next; // no NULL if howmany has run out
#ifndef STACKMAP_FT_SCB
		bq->bq_len = 0;
#endif
		/* suspend processing */
#ifdef STACKMAP_FT_SCB
		if (next == STACKMAP_FT_NULL) { // this fd is done
			n++;
			bq = ft->fde + ft->fds[n];
		}
		if (n < ft->nfds) { // we haven't done
			if (next != STACKMAP_FT_NULL)
				bq->bq_head = next;
			memmove(ft->fds, ft->fds + n,
				sizeof(ft->fds[0]) * (ft->nfds - n));
		}
		ft->nfds -= n;
		ft->npkts -= sent;
#endif
	}

	rxkring->nr_hwtail = j;
	mtx_unlock(&rxkring->q_lock);

	rxkring->nm_notify(rxkring, 0);
	rxkring->nkr_hwlease = rxkring->nr_hwcur;

	/* nm_notify processed all the packets, now swap out necessary ones */
	for (j = 0; j < nonfree_num; j++) {
		struct netmap_slot *slot = &rxkring->ring->slot[nonfree[j]];

		if (stackmap_extra_enqueue(kring, slot)) {
			/* Don't reclaim on/after this postion */
			u_int me = slot - rxkring->ring->slot;
			rxkring->nkr_hwlease = me;
			break;
		}
	}

	if (ft->npkts) { // we have leftover, cannot report k
		for (j = kring->nr_hwcur; j != k; j = nm_next(j, lim_tx)) {
			struct netmap_slot *slot = &kring->ring->slot[j];
			struct stackmap_cb *scb;
		       
			if (!slot->len)
				continue;
			scb = STACKMAP_CB_NMB(NMB(na, slot),
					NETMAP_BUF_SIZE(na));
			if (!stackmap_cb_valid(scb)) {
				D("invalidated scb %u?", j);
			}
			if (stackmap_cb_get_state(scb) != SCB_M_NOREF)
				break;
		}
		k = j;
	}
unlock_out:
	if (rx)
		local_bh_enable();
	netmap_bdg_runlock(vpna->na_bdg);
	return k;
}

static int
stackmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct stackmap_adapter *sna = (struct stackmap_adapter *)kring->na;
	struct nm_bridge *b = sna->up.na_bdg;
	u_int me = kring - NMR(kring->na, NR_RX);
	int i, err;

	/* TODO scan only necessary ports */
	err = netmap_vp_rxsync(kring, flags); // reclaim buffers released
	if (err)
		return err;
	if (!stackmap_no_runtocomp) {
		for_bdg_ports(i, b) {
			struct netmap_vp_adapter *vpna = netmap_bdg_port(b, i);
			struct netmap_adapter *na = &vpna->up;
			struct netmap_adapter *hwna;
			struct netmap_kring *hwkring;
	
			if (netmap_bdg_idx(vpna) == netmap_bdg_idx(&sna->up))
				continue;
			else if (stackmap_is_host(na))
				continue;
			if (unlikely(!nm_is_bwrap(na)))
				panic("no bwrap attached");

			/* We assume the same number of hwna with vpna
			 * (see netmap_bwrap_attach()) */
			hwna = ((struct netmap_bwrap_adapter *)vpna)->hwna;
			hwkring = NMR(hwna, NR_RX) +
				(na->num_tx_rings > me ? me : 0);
			SD(SD_QUE, 1, "intr");
			netmap_bwrap_intr_notify(hwkring, flags);
		}
	}
	return 0;
}


static int
stackmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	u_int const head = kring->rhead;
	u_int done;

	if (!((struct netmap_vp_adapter *)na)->na_bdg) {
		done = head;
		return 0;
	}
	//local_bh_disable();
	done = stackmap_bdg_flush(kring);
	//local_bh_enable();
	SD(SD_TX, 0, "hwcur from %u to %u (head %u)",
			kring->nr_hwcur, done, head);
	kring->nr_hwcur = done;
	kring->nr_hwtail = nm_prev(done, kring->nkr_num_slots - 1);
	return 0;
}

int
stackmap_transmit(struct ifnet *ifp, struct mbuf *m)
{
	struct netmap_adapter *na = NA(ifp);
	struct stackmap_cb *scb;
	struct netmap_slot *slot;
	int mismatch;

	SDPKT(SD_TX, 0, m->data);

	/* txsync-ing packets are always frags */
	if (!MBUF_NONLINEAR(m)) {
csum_transmit:
	       	if (nm_os_mbuf_has_offld(m)) {
			struct nm_iphdr *iph;
			char *th;
			uint16_t *check;

			iph = MBUF_NETWORK_HEADER(m);
			KASSERT(ntohs(iph->tot_len) >= 46,
			    ("too small UDP packet %d", ntohs(iph->tot_len)));
			th = MBUF_TRANSPORT_HEADER(m);
			if (iph->protocol == IPPROTO_UDP) {
				check = &((struct nm_udphdr *)th)->check;
			} else if (iph->protocol == IPPROTO_TCP) {
				check = &((struct nm_tcphdr *)th)->check;
			} else {
				panic("bad proto %u w/ offld", iph->protocol);
			}
			/* With ethtool -K eth1 tx-checksum-ip-generic on, we
			 * see HWCSUM/IP6CSUM in dev and ip_sum PARTIAL on m.
			 */
			*check = 0;
			nm_os_csum_tcpudp_ipv4(iph, th, skb_tail_pointer(m)
					- skb_transport_header(m), check);
			m->ip_summed = 0;
		}
		SDPKT(SD_QUE, 0, m->data);
		netmap_transmit(ifp, m);
		return 0;
	}

	/* Possibly from sendpage() context */
	if (skb_shinfo(m)->nr_frags > 1) {
		SD(SD_QUE, 0, "nr_frags %d", skb_shinfo(m)->nr_frags);
		SDPKT(SD_QUE, 0, m->data);
	}
	scb = STACKMAP_CB_EXT(m, 0, NETMAP_BUF_SIZE(na));
	if (unlikely(stackmap_cb_get_state(scb) != SCB_M_STACK)) {
		SD(SD_TX, 0, "nonlinear nonsendpage scb %p", scb);
		skb_linearize(m); // XXX
		goto csum_transmit;
	}

	/* Valid scb, txsync-ing packet. */
	slot = scb_slot(scb);
	if (stackmap_cb_get_state(scb) == SCB_M_QUEUED) {
	       	/* originated by netmap but has been queued in either extra
		 * or txring slot. The backend might drop this packet.
		 */
		struct stackmap_cb *scb2;
		int i, n = skb_shinfo(m)->nr_frags;

		for (i = 0; i < n; i++) {
			scb2 = STACKMAP_CB_EXT(m, i, NETMAP_BUF_SIZE(na));
			stackmap_cb_set_state(scb2, SCB_M_NOREF);
			SD(SD_QUE, 0,
				"queued xmit frag[%d] scb %p flags 0x%08x",
					i, scb2, scb2->flags);
		}
		slot->len = 0; // XXX
		MBUF_LINEARIZE(m);
		goto csum_transmit;
	}
	SD(SD_TX, 0, "direct scb %p", scb);

	/* bring protocol headers in */
	mismatch = MBUF_HEADLEN(m) - (int)slot->offset;
	if (!mismatch) {
		/* Length has already been validated */
		memcpy(NMB(na, slot) + na->virt_hdr_len, m->data, slot->offset);
	} else {
		SD(SD_TX, 1, "mismatch %d, copy entire data", mismatch);
		m_copydata(m, 0, MBUF_LEN(m), NMB(na, slot) + na->virt_hdr_len);
		slot->len += mismatch;
	}

	if (nm_os_mbuf_has_offld(m)) {
		struct nm_iphdr *iph;
		struct nm_tcphdr *tcph;
		uint16_t *check;
		int len;

		iph = (struct nm_iphdr *) ((char *)NMB(na, slot) +
			 na->virt_hdr_len + skb_network_offset(m));
		tcph = (struct nm_tcphdr *) ((char *)NMB(na, slot) +
			 na->virt_hdr_len + skb_transport_offset(m));
		check = &tcph->check;
		*check = 0;
		len = slot->len - na->virt_hdr_len - skb_transport_offset(m);
		nm_os_csum_tcpudp_ipv4(iph, tcph, len, check);
	}

	stackmap_add_fdtable(scb, scb_kring(scb));

	/* We don't know when the stack actually releases the data;
	 * it might holds reference via clone.
	 */
	stackmap_cb_set_state(scb, SCB_M_TXREF);
	nm_set_mbuf_data_destructor(m, &scb->ui,
			nm_os_stackmap_mbuf_data_destructor);
	m_freem(m);
	return 0;
}

/* XXX Ugly to separate from reg_slaves(), but we cannot detach
 * slaves by name as get_bnsbridges() fails due to lack of current.
 */
static void
stackmap_unreg_slaves(struct netmap_adapter *na) {
	struct stackmap_adapter *sna = (struct stackmap_adapter *)na;
	struct nm_bridge *b = sna->up.na_bdg;
	int i, me = netmap_bdg_idx(&sna->up);

	for_bdg_ports(i, b) {
		struct netmap_adapter *slave = &netmap_bdg_port(b, i)->up;
		struct netmap_adapter *hwna;
		struct lut_entry *lut;

		if (i == me)
			continue;
		hwna = ((struct netmap_bwrap_adapter *)slave)->hwna;
		lut = hwna->na_lut.lut;
		netmap_adapter_get(slave);
		slave->nm_bdg_ctl(slave, NULL, 0);
		/* restore default start_xmit for future register */
		((struct netmap_hw_adapter *)
		    hwna)->nm_ndo.ndo_start_xmit = linux_netmap_start_xmit;
		netmap_adapter_put(slave);
	}
}

static int
stackmap_reg_slaves(struct netmap_adapter *na)
{
	struct stackmap_adapter *sna = (struct stackmap_adapter *)na;
	char *tok, *s, *s_orig;
	int error = 0;
	struct nmreq nmr;
	char *p = nmr.nr_name;

	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	nmr.nr_cmd = NETMAP_BDG_ATTACH;
	/* Regular host stack port for indirect packets */
	nmr.nr_arg1 = NETMAP_BDG_HOST;
	p += strlcat(p, ":", sizeof(nmr.nr_name) - 
		strlcpy(p, netmap_bdg_name(&sna->up), sizeof(nmr.nr_name)));
	if (!sna->suffix)
		return 0;

	s = strdup(sna->suffix, M_DEVBUF);
	if (!s)
		return ENOMEM;
	s_orig = s;
	while ((tok = strsep(&s, "+")) != NULL &&
	    strncmp(tok, p, strlen(tok))) {
		struct netmap_adapter *slave = NULL;
		struct netmap_bwrap_adapter *bna;
		struct netmap_adapter *hwna;
		struct netmap_hw_adapter *h;
		struct netmap_adapter *vpna;
		int i;

		strlcpy(p, tok, strlen(tok) + 1);
		error = netmap_get_bdg_na(&nmr, &slave, na->nm_mem, 1);
		if (error)
			continue;
		if (!slave || !nm_is_bwrap(slave) /* XXX ugly */) {
			D("no error on get_bdg_na() but no valid adapter");
			netmap_adapter_put(slave);
			continue;
		}

		bna = (struct netmap_bwrap_adapter *)slave;
		vpna = &bna->up.up;
		hwna = bna->hwna;

		KASSERT(na->nm_mem == slave->nm_mem, "slave has different mem");

		/* For the first slave now it is the first time to have ifp
		 * We must set buffer offset before finalizing at nm_bdg_ctl()
		 * callback. As we see, we adopt the value for the first NIC */
		slave->virt_hdr_len = hwna->virt_hdr_len = na->virt_hdr_len;
		if (hwna->na_flags & NAF_HOST_RINGS)
			bna->host.up.virt_hdr_len = slave->virt_hdr_len;
		error = slave->nm_bdg_ctl(slave, &nmr, 1);
		if (error) {
			netmap_adapter_put(slave);
			continue;
		}

		/* we don't have keep original intr_notify() as
		 * we do this after original reg callback
		 */
		if (!stackmap_no_runtocomp) {
			for (i = 0; i < hwna->num_rx_rings; i++) {
				hwna->rx_rings[i].nm_notify = 
					stackmap_intr_notify;
			}
			/*
			for (i = 0; i < hwna->num_tx_rings; i++) {
				hwna->tx_rings[i].nm_notify =
					stackmap_intr_notify;
			}
			*/
		}
		for (i = 0; i < vpna->num_tx_rings; i++)
			vpna->tx_rings[i].nm_sync = stackmap_txsync;
		/* packets originated by the host stack
		 * simply go into the bridge
		 */
		if (bna->host.na_bdg) {
			vpna->tx_rings[i].nm_sync = stackmap_txsync;
		}

		/* na->if_transmit already has backup */
		h = (struct netmap_hw_adapter *)hwna;
#ifdef linux
		h->nm_ndo.ndo_start_xmit =
			linux_stackmap_start_xmit;
		/* re-overwrite */
		hwna->ifp->netdev_ops = &h->nm_ndo;
#else // not supported yet
#endif /* linux */
	}
	nm_os_free(s_orig);
	return error;
}

/*
 * When stackmap dies first, it simply restore all the socket
 * information on dtor().
 * Otherwise our sk->sk_destructor will cleanup stackmap states
 */
static void
stackmap_unregister_socket(struct stackmap_sk_adapter *ska)
{
	NM_SOCK_T *sk = ska->sk;
	struct stackmap_adapter *sna = (struct stackmap_adapter *)ska->na;

	if (ska->fd < sna->sk_adapters_max)
		sna->sk_adapters[ska->fd] = NULL;
	else
		D("unregistering non-registered fd %d", ska->fd);
	NM_SOCK_LOCK(sk);
	RESTORE_DATA_READY(sk, ska);
	RESTORE_DESTRUCTOR(sk, ska);
	stackmap_wsk(NULL, sk);
	NM_SOCK_UNLOCK(sk);
	nm_os_free(ska);
	SD(SD_GEN, 0, "unregistered fd %d sk %p", ska->fd, sk);
}

static void
stackmap_sk_destruct(NM_SOCK_T *sk)
{
	struct stackmap_sk_adapter *ska;
	struct stackmap_adapter *sna;

	ska = stackmap_sk(sk);
	SD(SD_GEN, 0, "sk %p ska %p", sk, ska);
	if (ska->save_sk_destruct) {
		ska->save_sk_destruct(sk);
	}
	sna = (struct stackmap_adapter *)ska->na;
	netmap_bdg_wlock(sna->up.na_bdg);
	stackmap_unregister_socket(ska);
	netmap_bdg_wunlock(sna->up.na_bdg);
}

static int
stackmap_register_fd(struct netmap_adapter *na, int fd)
{
	NM_SOCK_T *sk;
	struct stackmap_sk_adapter *ska;
	struct stackmap_adapter *sna = (struct stackmap_adapter *)na;
	int on = 1;

	/* first check table size */
	if (fd >= sna->sk_adapters_max) {
		struct stackmap_sk_adapter **old = sna->sk_adapters, **new;
		int oldsize = sna->sk_adapters_max;
		int newsize = oldsize ? oldsize * 2 : DEFAULT_SK_ADAPTERS;

		new = nm_os_malloc(sizeof(new) * newsize);
		if (!new) {
			D("failed to extend fd->sk_adapter table");
			return ENOMEM;
		}
		if (old) {
			memcpy(new, old, sizeof(old) * oldsize);
			nm_os_free(old);
		}
		sna->sk_adapters = new;
		sna->sk_adapters_max = newsize;
	}

	sk = nm_os_sock_fget(fd);
	if (!sk)
		return EINVAL;
	if (kernel_setsockopt(sk->sk_socket, SOL_TCP, TCP_NODELAY,
				(char *)&on, sizeof(on)) < 0) {
		SD(SD_GEN, 0, "WARNING: failed setsockopt(TCP_NODELAY)");
	}

	ska = nm_os_malloc(sizeof(*ska));
	if (!ska) {
		nm_os_sock_fput(sk);
		return ENOMEM;
	}
	if (sk->sk_data_ready != nm_os_stackmap_data_ready)
		SAVE_DATA_READY(sk, ska);
	if (sk->sk_destruct != stackmap_sk_destruct)
		SAVE_DESTRUCTOR(sk, ska);
	ska->na = na;
	ska->sk = sk;
	ska->fd = fd;
	SET_DATA_READY(sk, nm_os_stackmap_data_ready);
	SET_DESTRUCTOR(sk, stackmap_sk_destruct);
	stackmap_wsk(ska, sk);
	sna->sk_adapters[fd] = ska;


	nm_os_sock_fput(sk);
	SD(SD_GEN, 0, "registered fd %d sk %p ska %p", fd, sk, ska);
	return 0;
}

static void
stackmap_bdg_dtor(const struct netmap_vp_adapter *vpna)
{
	struct stackmap_adapter *sna;
	int i;

	if (&vpna->up != stackmap_master(&vpna->up))
		return;

	sna = (struct stackmap_adapter *)vpna;
	for (i = 0; i < sna->sk_adapters_max; i++) {
		struct stackmap_sk_adapter *ska = sna->sk_adapters[i];
		if (ska)
			stackmap_unregister_socket(ska);
	}
	nm_os_free(sna->sk_adapters);
	sna->sk_adapters_max = 0;
}

static int
stackmap_bdg_config(struct nm_ifreq *ifr,
			struct netmap_vp_adapter *vpna)
{
	int fd = *(int *)ifr->data;
	struct netmap_adapter *na = &vpna->up;

	return stackmap_register_fd(na, fd);
}


static void
stackmap_extra_free(struct netmap_adapter *na)
{
	enum txrx t;

	for_rx_tx(t) {
		int i;

		for (i = 0; i < netmap_real_rings(na, t); i++) {
			struct netmap_kring *kring = &NMR(na, t)[i];
			struct extra_pool *extra;

			if (!kring->extra)
				continue;
			extra = kring->extra;
			if (extra->slots)
				nm_os_free(extra->slots);
			if (extra->num) {
				int j;

				/* Build a returning buffer list */
				for (j = 0; j < extra->num; j++) {
					u_int idx = extra->slots[j].buf_idx;
					if (idx >= 2)
						extra->bufs[j] = idx;
				}
				netmap_extra_free(na, extra->bufs, 1);
				nm_os_free(extra->bufs);
			}
			extra->num = 0;
			nm_os_free(extra);
		}
	}
}

static int
stackmap_extra_alloc(struct netmap_adapter *na)
{
	enum txrx t;

	for_rx_tx(t) {
		int i;

		/* XXX probably we don't need extra on host rings */
		for (i = 0; i < netmap_real_rings(na, t); i++) {
			struct netmap_kring *kring = &NMR(na, t)[i];
			struct extra_pool *extra;
			uint32_t *extra_bufs;
			struct netmap_slot *extra_slots;
			u_int want = stackmap_extra, n, j;

			extra = nm_os_malloc(sizeof(*kring->extra));
			if (!extra)
				break;
			kring->extra = extra;

			extra_bufs = nm_os_malloc(sizeof(*extra_bufs) *
					(want + 1));
			if (!extra_bufs)
				break;
			kring->extra->bufs = extra_bufs;

			n = netmap_extra_alloc(na, extra_bufs, want, 1);
			if (n < want)
				D("allocated only %u bufs", n);
			kring->extra->num = n;

			extra_slots = nm_os_malloc(sizeof(*extra_slots) * n);
			if (!extra_slots)
				break;
			for (j = 0; j < n; j++) {
				struct netmap_slot *slot = &extra_slots[j];

				slot->buf_idx = extra_bufs[j];
				slot->len = 0;
			}
			kring->extra->slots = extra_slots;
		}
		/* rollaback on error */
		if (i < netmap_real_rings(na, t)) {
			stackmap_extra_free(na);
			return ENOMEM;
		}
	}
	return 0;
}

int
stackmap_reg(struct netmap_adapter *na, int onoff)
{
	struct stackmap_adapter *sna = (struct stackmap_adapter *)na;
	int err;

	D("%s (%p) onoff %d suffix: %s",
		na->name, sna, onoff,
		sna->suffix[0] ? sna->suffix : "none");
	err = sna->save_reg(na, onoff);
	if (err)
		return err;
	if (onoff) {
		struct netmap_bdg_ops ops
			= {NULL, stackmap_bdg_config, stackmap_bdg_dtor};
		if (stackmap_extra_alloc(na))
			return err;
		/* install config handler */
		netmap_bdg_set_ops(sna->up.na_bdg, &ops);
#ifdef STACKMAP_CB_TAIL
		na->virt_hdr_len = STACKMAP_DMA_OFFSET;
#else
		na->virt_hdr_len = sizeof(struct stackmap_cb);
#endif /* STACKMAP_CB_TAIL */
#ifdef NETMAP_MEM_MAPPING
		//netmap_mem_set_buf_offset(na->nm_mem, na->virt_hdr_len);
#endif /* NETMAP_MEM_MAPPING */

		return stackmap_reg_slaves(na);
	}
	stackmap_unreg_slaves(na);
	return 0;
}

/* allocating skb is postponed until krings are created on register */
static int
stackmap_attach(struct netmap_adapter *arg, struct netmap_adapter **ret,
		const char *suffix)
{
	struct netmap_vp_adapter *vparg = (struct netmap_vp_adapter *)arg;
	struct nm_bridge *b = vparg->na_bdg;
	struct stackmap_adapter *sna;
	struct netmap_vp_adapter *vpna;
	struct netmap_adapter *na;


	sna = nm_os_malloc(sizeof(*sna));
	if (sna == NULL)
		return ENOMEM;
	vpna = &sna->up;
	/* copy everything and replace references from hwna and bridge */
	*vpna = *((struct netmap_vp_adapter *)arg);
	vpna->up.na_vp = vpna;
	netmap_bdg_wlock(b);
	netmap_set_bdg_port(b, vpna->bdg_port, vpna);
	nm_os_free(arg);

	na = &vpna->up;
	sna->save_reg = na->nm_register;
	na->nm_register = stackmap_reg;
	na->nm_txsync = stackmap_txsync;
	na->na_flags |= NAF_BDG_MBUF;
	na->nm_rxsync = stackmap_rxsync;
	strncpy(sna->suffix, suffix, sizeof(sna->suffix));
	netmap_bdg_wunlock(b);
	*ret = na;
	return 0;
}

int
netmap_get_stackmap_na(struct nmreq *nmr, struct netmap_adapter **ret,
	       	int create)
{
	struct netmap_adapter *na;
	int error;

	*ret = NULL;
	if (strncmp(nmr->nr_name, NM_STACK_NAME, strlen(NM_STACK_NAME)))
		return 0;

	/* XXX always a new, private allocator */
	error = netmap_get_bdg_na(nmr, &na, NULL, create);
	if (error) {
		D("error in get_bdg_na");
		return error;
	}
	/* only master port is extended */
	if (!nm_is_bwrap(na) && na->na_refcount == 1 /* just created */) {
		/* extend the original adapter */
		error = stackmap_attach(na, ret, nmr->nr_suffix);
	} else {
		*ret = na;
	}
	return error;
}
#endif /* WITH_STACK */
