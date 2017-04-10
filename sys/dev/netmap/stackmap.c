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
#define NM_STACKMAP_PULL 1
static int stackmap_mode = NM_STACKMAP_PULL;//NM_STACKMAP_PULL
//static int stackmap_mode = 0;
SYSBEGIN(vars_stack);
SYSCTL_DECL(_dev_netmap);
SYSCTL_INT(_dev_netmap, OID_AUTO, stackmap_mode, CTLFLAG_RW, &stackmap_mode, 0 , "");
SYSEND;

#define NM_RANGE(v, s, n, k)	\
	(((int)s + n < (int)k->nkr_num_slots) ?\
	 (v >= (int)s && v < (int)s + n) : \
	  ((v >= (int)s && v < (int)k->nkr_num_slots) || \
	   (v < (int)s + n - (int)k->nkr_num_slots)))

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
	ND("%s interrupt (kring %p)", t == NR_TX ? "tx" : "rx", kring);
	if (mna) {
		struct netmap_kring *mkring;
		u_int me = kring - NMR(na, t), mnr;

		if (stackmap_mode != NM_STACKMAP_PULL)
			return netmap_bwrap_intr_notify(kring, flags);
		mnr = t == NR_RX ? mna->num_rx_rings : mna->num_tx_rings;
		mkring = &NMR(mna, t)[mnr > me ? me : 0];
		mkring->nm_notify(mkring, 0);
	}
	return NM_IRQ_COMPLETED;
}

/* Stackmap version of the flush routine.
 * We ask the stack to identify destination NIC.
 * Packets are moved around by buffer swapping
 * Unsent packets throttle the source ring
 * Packets are re-iterated after dst->notify, 
 * TODO currently just forward all the packets
 * TODO consider if we can merge this with the original flush routine.
 */
enum {
	NM_STACK_CONSUMED=0,
	NM_STACK_DEFERRED,
	NM_STACK_CONSUMED_RESERVING,
};

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
		D("ft full");
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

static inline uint32_t
stackmap_kr_rxspace(struct netmap_kring *k)
{
	int space;
	int busy = k->nr_hwtail - k->nr_hwcur;

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
	bool rx = 0, host = stackmap_is_host(na); // shorthands
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
		RD(1, "failed to obtain rlock");
		return 0;
	}

	/* XXX perhaps this is handled later? */
	if (netmap_bdg_active_ports(vpna->na_bdg) < 2) {
		RD(1, "only %d active ports",
				netmap_bdg_active_ports(vpna->na_bdg));
		goto unlock_out;
	}

	/* let the host stack packets go earlier */

	if (na == stackmap_master(na) || host) {
		rxna = &netmap_bdg_port(vpna->na_bdg, 1)->up; /* XXX */
	} else {
		rxna = stackmap_master(na);
		rx = 1;
	}

	/* XXX we simply skip processed slots */

	for (k = kring->nr_hwcur; k != rhead; k = nm_next(k, lim_tx)) {
		struct netmap_slot *slot = &kring->ring->slot[k];
		struct stackmap_cb *scb;
		char *nmb = NMB(na, slot);
		int error;

		if (unlikely(slot->len == 0))
			continue;
		if (NM_RANGE(k, kring->nr_hwcur, leftover, kring)) {
			RD(1, "skiping leftover slot %d", k);
			continue;
		}
		scb = STACKMAP_CB_NMB(nmb, NETMAP_BUF_SIZE(na));
		__builtin_prefetch(scb);
		if (unlikely(host)) { // XXX no batch in host
			slot->fd = STACKMAP_FD_HOST;
			scbw(scb, kring, slot);
			stackmap_cb_set_state(scb, SCB_M_NOREF);
			stackmap_add_fdtable(scb, kring);
			continue;
		}
		if (unlikely(stackmap_cb_get_state(scb) == SCB_M_QUEUED)) {
			/* hold by the stack and sits on this ring */
			ND(1, "M_QUEUED, extra_enqueue");
			if (stackmap_extra_enqueue(na, slot)) {
				break;
			}
			continue;
		}
		if (stackmap_cb_get_state(scb) == SCB_M_NOREF ||
		    stackmap_cb_get_state(scb) == SCB_M_STACK) {
			/* leftover (leftover <= rhead - hwcur) */
			if (unlikely(!NM_RANGE(k, kring->nr_hwcur,
							leftover,kring))) {
				RD(1, "weird, M_NOREF but not in leftover... (k %d hwcur %d leftover %d nslots %d)", k, kring->nr_hwcur, leftover, kring->nkr_num_slots);
			}
			continue;
		}
		stackmap_cb_invalidate(scb);
		scbw(scb, kring, slot);
		error = rx ? nm_os_stackmap_recv(na, slot) :
			     nm_os_stackmap_send(na, slot);
		if (unlikely(error)) {
			RD(1, "early break");
			break;
		}
	}
	if (rx) {
		ND("rx %d packets", (rhead - (int)kring->nr_hwcur >= 0 ?
		       	rhead - kring->nr_hwcur :
			rhead + kring->nkr_num_slots - kring->nr_hwcur));
	}

	/* Now, we know how many packets go to the receiver
	 * On TX we can drop packets with handling packets with 
	 * references appropriately.
	 * On RX we cannot do so.
	 */

	if (unlikely(!nm_netmap_on(rxna))) {
		D("BUG: we cannot handle this case now!");
		goto unlock_out;
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
	if (ft->npkts < howmany)
		howmany = ft->npkts;

	/* TODO Apr.7: Swap out packets with references (i.e., M_STACK) */
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
			if (stackmap_cb_get_state(scb) == SCB_M_STACK) {
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

	/*
	 * All packets have been processed by the backend.
	 * We now swap out those still hold by the stack (SCB_M_STACK)
	 */
	for (j = 0; j < nonfree_num; j++) {
		struct netmap_slot *slot = &rxkring->ring->slot[nonfree[j]];

		if (stackmap_extra_enqueue(na, slot)) {
			panic("enqueue failed");
		}
	}

	if (ft->npkts) { // we have leftover, cannot report k
		for (j = kring->nr_hwcur; j != k; j = nm_next(j, lim_tx)) {
			if (kring->ring->slot[j].len > 0) // not sent
				break;
		}
		ND(1, "%d leftovers (hwcur %d inuse %d head %d)",
			ft->npkts, kring->nr_hwcur, j, rhead);
		k = j;
	}
unlock_out:
	netmap_bdg_runlock(vpna->na_bdg);
	return k;
}

/* rxsync for stackport */
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
	if (stackmap_mode == NM_STACKMAP_PULL) {
		ND("kr %p rhead %u hwcur %u tail %u lease %u nslots %u", kring, kring->rhead, kring->nr_hwcur, kring->nr_hwtail, kring->nkr_hwlease, kring->nkr_num_slots);
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
	/*
	done = (na == stackmap_master(na) || stackmap_is_host(na)) ?
	       	stackmap_bdg_flush(kring) : stackmap_bdg_rx(kring);
		*/
	done = stackmap_bdg_flush(kring);
	/* debug to drain everything */
	//kring->nr_hwcur = head;
	//kring->nr_hwtail = nm_prev(head, kring->nkr_num_slots - 1);
	kring->nr_hwcur = done;
	kring->nr_hwtail = nm_prev(done, kring->nkr_num_slots - 1);
	return 0;
}

#define ETHTYPE(p)	(ntohs(*(uint16_t *)((uint8_t *)(p)+12)))
#define NMIPHDR(p)	((struct nm_iphdr *)((uint8_t *)(p)+14))
#define NMTCPHDR(p)	((struct nm_tcphdr *)((uint8_t *)NMIPHDR(p) + 20))
#define TCPFLAG(p)	(NMIPHDR(p)->protocol == IPPROTO_TCP ? \
				NMTCPHDR(p)->flags : 0)

int
stackmap_ndo_start_xmit(struct mbuf *m, struct ifnet *ifp)
{
	struct netmap_adapter *na = NA(ifp);
	struct stackmap_cb *scb;
	struct netmap_slot *slot;
	int mismatch;

	/* this field has survived cloning */
	D("m %p head %p len %u space %u f %p len %u (0x%04x) %s headroom %u tcpflag 0x%02x",
		m, m->head, skb_headlen(m), skb_end_offset(m),
		skb_is_nonlinear(m) ?
			skb_frag_address(&skb_shinfo(m)->frags[0]): NULL,
		skb_is_nonlinear(m) ?
			skb_frag_size(&skb_shinfo(m)->frags[0]) : 0,
		ETHTYPE(m->data),
		skb_is_nonlinear(m)?"sendpage":"no-sendpage", skb_headroom(m),
		TCPFLAG(m->data));

	if (!skb_is_nonlinear(m)) {
transmit:
		netmap_transmit(ifp, m);
		return 0;
	}

	/* XXX We need a better way to distinguish m originated from stack */

	/* Possibly from sendpage() context */
	scb = STACKMAP_CB_FRAG(m, NETMAP_BUF_SIZE(na));
	if (unlikely(!stackmap_cb_valid(scb))) {
		D("m is nonlinear but not from our sendpage()");
		goto transmit;
	}

	/* because of valid scb, this is our packet. */

	slot = scb_slot(scb);
	if (stackmap_cb_get_state(scb) == SCB_M_QUEUED) {
	       	/* originated by netmap but has been queued in either extra
		 * or txring slot. The backend might drop this packet
		 * We don't need scb anymore.
		 */
		D("queued transmit scb %p", scb);
#if 0
		nm_set_mbuf_data_destructor(m, &scb->ui,
			nm_os_stackmap_mbuf_data_destructor);
		/* keep scb until the final reference goes away */
		slot->len = slot->offset = slot->next = 0;
#endif /* 0 */
		stackmap_cb_invalidate(scb);
		netmap_transmit(ifp, m);
		return 0;
	}

	//KASSERT(stackmap_cb_get_state(scb) == SCB_M_STACK, "invalid state");

	/* bring protocol headers in */
	mismatch = slot->offset - MBUF_HEADLEN(m);
	D("bring headers to %p: slot->off %u MHEADLEN(m) %u mismatch %d",
		NMB(na, slot), slot->offset, MBUF_HEADLEN(m), mismatch);
	if (!mismatch) {
		/* We need to copy only from head */
		ND("nmb %p frag %p (pageoff %d)", NMB(na, slot),
			skb_frag_address(&skb_shinfo(m)->frags[0]),
			skb_shinfo(m)->frags[0].page_offset);
		/* We have already validated length */
		//skb_copy_from_linear_data(m, NMB(na, slot) +
		//na->virt_hdr_len, slot->offset);
		memcpy(NMB(na, slot) + na->virt_hdr_len, m->data, slot->offset);
	} else {
		RD(1, "mismatch %d, copy entire data", mismatch);
		m_copydata(m, 0, MBUF_LEN(m), NMB(na, slot) + na->virt_hdr_len);
	}

	stackmap_add_fdtable(scb, scb_kring(scb));

	/* We don't know when the stack actually releases the data
	 * or it might holds reference via clone
	 */

	nm_set_mbuf_data_destructor(m, &scb->ui,
			nm_os_stackmap_mbuf_data_destructor);
	m_freem(m);
	return 0;
}

/* XXX Really ugly to separate from reg_slaves(), but we cannot detach
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
	ND("done for slaves");
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
		ND("registering %s (tok %s)", nmr.nr_name, tok);
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
		error = slave->nm_bdg_ctl(slave, &nmr, 1);
		if (error) {
			netmap_adapter_put(slave);
			continue;
		}

		/* we don't have keep original intr_notify() as
		 * we do this after original reg callback
		 */
		if (stackmap_mode == NM_STACKMAP_PULL) {
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
		h->nm_ndo.ndo_start_xmit =
			stackmap_ndo_start_xmit;
		/* re-overwrite */
		hwna->ifp->netdev_ops = &h->nm_ndo;
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
	D("unregistered fd %d", ska->fd);
}

static void
stackmap_sk_destruct(NM_SOCK_T *sk)
{
	struct stackmap_sk_adapter *ska;
	struct stackmap_adapter *sna;

	ska = stackmap_sk(sk);
	if (ska->save_sk_destruct) {
		ska->save_sk_destruct(sk);
	}
	sna = (struct stackmap_adapter *)ska->na;
	netmap_bdg_wlock(sna->up.na_bdg);
	stackmap_unregister_socket(ska);
	netmap_bdg_wunlock(sna->up.na_bdg);
	D("unregistered socket");
}

static int
stackmap_register_fd(struct netmap_adapter *na, int fd)
{
	NM_SOCK_T *sk;
	struct stackmap_sk_adapter *ska;
	struct stackmap_adapter *sna = (struct stackmap_adapter *)na;

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

	ska = nm_os_malloc(sizeof(*ska));
	if (!ska) {
		nm_os_sock_fput(sk);
		return ENOMEM;
	}
	SAVE_DATA_READY(sk, ska);
	SAVE_DESTRUCTOR(sk, ska);
	ska->na = na;
	ska->sk = sk;
	ska->fd = fd;
	SET_DATA_READY(sk, nm_os_stackmap_data_ready);
	SET_DESTRUCTOR(sk, stackmap_sk_destruct);
	stackmap_wsk(ska, sk);
	sna->sk_adapters[fd] = ska;

	nm_os_sock_fput(sk);
	D("registered fd %d sk %p ska %p", fd, sk, ska);
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

#define STACKMAP_NUM_EXTRA_BUFS	4
//static uint32_t stackmap_extra_bufs[STACKMAP_NUM_EXTRA_BUFS+1];
int
stackmap_reg(struct netmap_adapter *na, int onoff)
{
	struct stackmap_adapter *sna = (struct stackmap_adapter *)na;
	int i, err;

	D("%s (%p) onoff %d suffix: %s",
		na->name, sna, onoff,
		sna->suffix[0] ? sna->suffix : "none");
	err = sna->save_reg(na, onoff);
	if (err)
		return err;
	if (onoff) {
		uint32_t *extra_bufs, n;
		struct netmap_slot *extra_slots;
		struct netmap_bdg_ops ops
			= {NULL, stackmap_bdg_config, stackmap_bdg_dtor};

		/* one extra to store the terminating 0 */
		extra_bufs = nm_os_malloc(sizeof(uint32_t)
		    * STACKMAP_NUM_EXTRA_BUFS + 1);
		if (!extra_bufs) {
			sna->save_reg(na, 0);
			return ENOMEM;
		}
		n = netmap_extra_alloc(na, extra_bufs,
			STACKMAP_NUM_EXTRA_BUFS, 1);
		if (n < STACKMAP_NUM_EXTRA_BUFS)
			D("allocated only %d bufs", n);
		extra_slots = nm_os_malloc(
		    sizeof(struct netmap_slot) * n);
		if (!extra_slots) {
			D("malloc failed for extra slots");
			netmap_extra_free(na, extra_bufs, 1);
			sna->save_reg(na, 0);
			nm_os_free(extra_bufs);
			return ENOMEM;
		}
		for (i = 0; i < n; i++) {
			struct netmap_slot *slot;
		       
			slot = &extra_slots[i];
			slot->buf_idx = extra_bufs[i];
			slot->len = 0;
		}
		sna->extra_bufs = extra_bufs;
		sna->extra_num = n;
		sna->extra_slots = extra_slots;

		/* install config handler */
		netmap_bdg_set_ops(sna->up.na_bdg, &ops);
#ifdef STACKMAP_CB_TAIL
		na->virt_hdr_len = STACKMAP_DMA_OFFSET;
#else
		na->virt_hdr_len = sizeof(struct stackmap_cb);
#endif /* STACKMAP_CB_TAIL */
		D("virt_hdr_len %d", na->virt_hdr_len);
		netmap_mem_set_buf_offset(na->nm_mem, na->virt_hdr_len);

		return stackmap_reg_slaves(na);
	}

	/* Build a returning buffer list */
	for (i = 0; i < sna->extra_num; i++) {
		u_int idx = sna->extra_slots[i].buf_idx;
		if (idx >= 2)
			sna->extra_bufs[i] = idx;
	}
	nm_os_free(sna->extra_slots);
	netmap_extra_free(na, sna->extra_bufs, 1);
	nm_os_free(sna->extra_bufs);
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
	ND("%s 0x%p (orig 0x%p) mem 0x%p master %d bwrap %d",
	       	na->name, na, arg, na->nm_mem, master, !!nm_is_bwrap(na));

	ND("done (sna %p)", sna);
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
