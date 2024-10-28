// SPDX-License-Identifier: GPL-2.0-or-later
/* LGCC congestion control.
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include "tcp_lgc.h"
#include "tcp_lgcc.h"
#include "tcp_dctcp.h"

#define SHIFT		16
#define ONE		(1U<<SHIFT)
#define MAX_FRACTION	65470U;	/* 0.999 x ONE */

struct lgcc {
	/* Rate recalculation logic */
	u32 next_seq;		/* Sequence number RTT will expire on */
	u64 next_timestamp;	/* Timestamp RTT will expire on */
	u8 rate_eval:1;		/* Boolean: rate has been evaluated before */

	/* Rate calculation */
	u32 old_delivered;	/* Last total packets delivered */
	u32 old_delivered_ce;	/* Last CE-marked packets packets */
	u64 s_max_rate;		/* Shifted max rate */
	u64 s_rate;		/* Shifted current sending rate */
	u64 s_tx_next_rate;	/* Shifted transmitted next LGCC loop rate */
	u64 s_rx_next_rate;	/* Shifted received next LGCC loop rate */
	u32 s_fraction;		/* Shifted fraction of CE-marked packets */

	/* For the DCTCP state machine */
	u32 prior_rcv_nxt;
	u32 ce_state;

	/* sysctl configurable variables */
	u32 max_rate;		/* Maximum sending rate */
	u32 min_rtt;		/* Minimum RTT */
	u32 static_rtt;		/* Boolean: static or dynamic RTT */
};

/* Module parameters */
/* lgcc_alpha_16 = alpha << 16 = 0.05 * 2^16 */
static unsigned int lgcc_alpha_16 __read_mostly = 3277;
module_param(lgcc_alpha_16, uint, 0644);
MODULE_PARM_DESC(lgcc_alpha_16, "scaled alpha");

static unsigned int thresh_16 __read_mostly = 52429;	/* ~0.8 << 16 */
module_param(thresh_16, uint, 0644);
MODULE_PARM_DESC(thresh_16, "scaled thresh");

/* End of Module parameters */

int sysctl_lgcc_max_rate[1] __read_mostly;	/* min/default/max */
int sysctl_lgcc_min_rtt[1] __read_mostly;	/* unit is micro sec (us) */
int sysctl_lgcc_static_rtt[1] __read_mostly;	/* boolean */

static void lgcc_reset(const struct tcp_sock *tp, struct lgcc *ca)
{
	ca->next_seq = tp->snd_nxt;
	ca->next_timestamp = ktime_get_ns() + ca->min_rtt * 1000;

	ca->old_delivered = tp->delivered;
	ca->old_delivered_ce = tp->delivered_ce;
}

static void tcp_lgcc_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	int max_rate;

	if ((sk->sk_state == TCP_LISTEN || sk->sk_state == TCP_CLOSE)
	    || 1) {
		/* || (tp->ecn_flags & TCP_ECN_OK)) { */
		/* FIXME: temporary hack! --Martin */
		struct lgcc *ca = inet_csk_ca(sk);

		/* Import sysctl settings */
		ca->min_rtt = sysctl_lgcc_min_rtt[0];
		ca->static_rtt = sysctl_lgcc_static_rtt[0];
		max_rate = sysctl_lgcc_max_rate[0];

		/* Set the max rate(s) */
		max_rate *= 125U;	/* * 1000 / 8 */
		ca->max_rate = (max_rate) ? (u32) (max_rate) : 1250000U;
		ca->s_max_rate = ((u64) (ca->max_rate)) << SHIFT;

		/* Other needed initialisations */
		ca->rate_eval = 0;
		ca->s_rate = ONE;
		ca->s_fraction = 0U;

		/* Set the "previous" control loop rate to be the maximum
		 * possible value. This will ensure we will not do any rate
		 * calculations based off it, before we get any signal, since
		 * LGCC's rate algorithm does a `min(s_rx_next_rate, ...)`. */
		ca->s_tx_next_rate = ULLONG_MAX;
		ca->s_rx_next_rate = ULLONG_MAX;

		/* Needed for the DCTCP state machine */
		ca->prior_rcv_nxt = tp->rcv_nxt;

		lgcc_reset(tp, ca);

		return;
	}
}

/* Calculate the initial rate of the flow in bytes/ms
 * rate = cwnd * mss / rtt_ms
 */
static void lgcc_init_rate(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct lgcc *ca = inet_csk_ca(sk);

	u64 s_init_rate = (u64) (tp->snd_cwnd * tp->mss_cache * 1000) << SHIFT;
	do_div(s_init_rate, ca->min_rtt);

	ca->s_tx_next_rate = ULLONG_MAX;
	ca->s_rx_next_rate = ULLONG_MAX;

	ca->s_rate = s_init_rate;
	ca->rate_eval = 1;
}

static void lgcc_update_rate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgcc *ca = inet_csk_ca(sk);
	u64 s_rate = ca->s_rate;
	u64 s_tmp_rate = ca->s_rate;
	u64 s_new_rate;
	u32 s_fraction;
	u32 s_growth;
	s64 s_rate_change;

	u32 delivered_ce = tp->delivered_ce - ca->old_delivered_ce;
	u32 delivered = tp->delivered - ca->old_delivered;
	u32 s_delivered_ce = (delivered_ce << SHIFT) / max(delivered, 1U);

	/* Compute the fraction of CE-marked packets */
	s_fraction = (ONE - lgcc_alpha_16) * ca->s_fraction;
	if (s_delivered_ce >= thresh_16)
		s_fraction += lgcc_alpha_16 * s_delivered_ce;
	ca->s_fraction = (s_fraction >> SHIFT);

	/* Ensure fraction does not exceed 100% */
	if (ca->s_fraction >= ONE)
		ca->s_fraction = MAX_FRACTION;

	/* If the next LGCC control loop is congested, use the received rate in
	 * the calculation instead of the configured max rate. */
	u64 divisor = min(ca->s_rx_next_rate, ca->s_max_rate) >> SHIFT;
	do_div(s_tmp_rate, max(divisor, 1U));

	/* Calculate the gradient */
	s32 s_gradient = lgc_log_lut_lookup((u32) s_tmp_rate)
	    - lgc_log_lut_lookup((u32) (ONE - ca->s_fraction));

	/* Calculate the growth rate */
	s_growth = lgc_pow_lut_lookup(s_delivered_ce);

	/* Calculate the rate change */
	s_rate_change = ((s_growth * s_rate) >> SHIFT) * s_gradient;

	/* Calculate preliminary new rate */
	s_new_rate = (u64) ((s_rate << SHIFT) + s_rate_change) >> SHIFT;

	/* The new rate should not increase more than twice, or be zero */
	if (s_new_rate > (s_rate << 1))
		s_rate <<= 1;
	else if (s_new_rate == 0)
		s_rate = ONE;
	else
		s_rate = s_new_rate;

	/* Check if the new rate exceeds the link capacity */
	if (s_rate > ca->s_max_rate)
		s_rate = ca->s_max_rate;

	/* s_rate can be read from lgcc_get_info() without synchronisation, 
	 * so we ask compiler to not use rate as a temporary variable in prior
	 * operations. */
	WRITE_ONCE(ca->s_rate, s_rate);
}

/* Calculate cwnd based on current rate and min_rtt
 * cwnd = rate * minRT / mss
 */
static void lgcc_set_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgcc *ca = inet_csk_ca(sk);

	/* We need to shift the rate down */
	u64 target = (u64) (ca->s_rate * ca->min_rtt) >> SHIFT;
	do_div(target, tp->mss_cache * 1000);

	/* Set cwnd. This is what actually affects the outgoing speed */
	tp->snd_cwnd = max_t(u32, (u32) target + 1, 2U);

	/* `clamp` is by default a u32 max value */
	if (tp->snd_cwnd > tp->snd_cwnd_clamp)
		tp->snd_cwnd = tp->snd_cwnd_clamp;
}

/* Get the rate of the next LGCC control loop, as advertised in the last
 * received ACK. This is executed every time we receive an ACK. */
void tcp_lgcc_get_next_rate_from_ack(struct sock *sk, u32 flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgcc *ca = inet_csk_ca(sk);
	WRITE_ONCE(ca->s_rx_next_rate, tp->rx_opt.lgcc_rate);
}

/* Transfer the calculated rate to another socket, for it to transmit in the 
 * next ACK. Called by the LGCC router (PEP-DNA). */
void tcp_lgcc_set_next_rate(struct sock *from, struct sock *to)
{
	struct lgcc *ca_to = inet_csk_ca(to);
	struct lgcc *ca_from = inet_csk_ca(from);
	WRITE_ONCE(ca_to->s_tx_next_rate, ca_from->s_rate);
}

EXPORT_SYMBOL(tcp_lgcc_set_next_rate);

/* Get the rate we would like to transmit (for the LGCC TCP option). Called
 * by the TCP (output) stack. */
u64 tcp_lgcc_get_next_rate(struct tcp_sock *tp)
{
	struct lgcc *ca = ((struct lgcc *)(tp->inet_conn.icsk_ca_priv));
	return ca->s_tx_next_rate;
}

EXPORT_SYMBOL(tcp_lgcc_get_next_rate);

/* From the DCTCP implementation, with minor modifications. */
__bpf_kfunc static void lgcc_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct lgcc *ca = inet_csk_ca(sk);

	switch (ev) {
	case CA_EVENT_ECN_IS_CE:
	case CA_EVENT_ECN_NO_CE:
		dctcp_ece_ack_update(sk, ev, &ca->prior_rcv_nxt, &ca->ce_state);
		break;
	default:
		/* Don't care for the rest. */
		break;
	}

	/* Trigger the rate calculation */
	lgcc_update_rate(sk);
}

/* XXX: A bit unsure if this is needed, and how to implement this. Now it
 * effectively removes slow start, I guess? This TCP module affects rate
 * via the cwnd primarily, not ssthresh. */
static u32 tcp_lgcc_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	return max(tcp_snd_cwnd(tp), 2U);
}

static void tcp_lgcc_main(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgcc *ca = inet_csk_ca(sk);
	bool rtt_expired;

	if (ca->static_rtt)
		/* With static RTT use an absolute measure */
		rtt_expired = ktime_get_ns() >= ca->next_timestamp;
	else
		/* With dynamic RTT use actual packet delivery */
		rtt_expired = !before(tp->snd_una, ca->next_seq);

	if (rtt_expired) {

		if (ca->static_rtt == false)
			ca->min_rtt = min_not_zero(tcp_min_rtt(tp),
						   ca->min_rtt);

		if (unlikely(!ca->rate_eval))
			lgcc_init_rate(sk);

		lgcc_update_rate(sk);
		lgcc_set_cwnd(sk);
		lgcc_reset(tp, ca);
	}
}

static size_t tcp_lgcc_get_info(struct sock *sk, u32 ext, int *attr,
				union tcp_cc_info *info)
{
	const struct lgcc *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Fill it also in case of VEGASINFO due to req struct limits.
	 * We can still correctly retrieve it later.
	 */
	if (ext & (1 << (INET_DIAG_LGCCINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		memset(&info->lgcc, 0, sizeof(info->lgcc));
		info->lgcc.lgcc_enabled = 1;
		info->lgcc.lgcc_rate = 65536000 >> SHIFT;
		info->lgcc.lgcc_ab_ecn = tp->mss_cache *
		    (tp->delivered_ce - ca->old_delivered_ce);
		info->lgcc.lgcc_ab_tot = tp->mss_cache *
		    (tp->delivered - ca->old_delivered);

		*attr = INET_DIAG_LGCCINFO;
		return sizeof(info->lgcc);
	}
	return 0;
}

static struct tcp_congestion_ops lgcc __read_mostly = {
	.init = tcp_lgcc_init,
	.cong_control = tcp_lgcc_main,
	.cwnd_event = lgcc_cwnd_event,
	.in_ack_event = tcp_lgcc_get_next_rate_from_ack,
	.ssthresh = tcp_lgcc_ssthresh,
	.undo_cwnd = tcp_reno_undo_cwnd,
	.get_info = tcp_lgcc_get_info,
	.flags = TCP_CONG_NEEDS_ECN,
	.owner = THIS_MODULE,
	.name = "lgcc",
};

static int __init lgcc_register(void)
{
	BUILD_BUG_ON(sizeof(struct lgcc) > ICSK_CA_PRIV_SIZE);
	lgcc_register_sysctl();
	sysctl_lgcc_max_rate[0] = 1000;
	sysctl_lgcc_min_rtt[0] = 1U << 20;	/* ~1s */
	sysctl_lgcc_static_rtt[0] = false;
	return tcp_register_congestion_control(&lgcc);
}

static void __exit lgcc_unregister(void)
{
	tcp_unregister_congestion_control(&lgcc);
	lgcc_unregister_sysctl();
}

module_init(lgcc_register);
module_exit(lgcc_unregister);

MODULE_AUTHOR("Martin Mihle Nygaard <martimn@ifi.uio.no>");
MODULE_LICENSE("GPL");
MODULE_VERSION("2.0");
MODULE_DESCRIPTION("LGCC");
