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
#include <linux/printk.h> /* FIXME: remove. For LGCC debugging. */
#include <linux/random.h>   /* FIXME: remove. For LGCC debugging. */

#define LGCC_SHIFT	16
#define ONE		(1U<<16)
#define THRESSH		52429U
#define BW_GAIN		((120U<<8)/100)

struct lgcc {
	u32 old_delivered;
	u32 old_delivered_ce;
	u32 next_seq;
	u64 rate;
	u64 rate_prev_loop_router_updated;
	u64 rate_prev_loop_ack_updated;
	u64 max_rateS;
	u32 mrate;
	u64 exp_rate;
	u32 minRTT;
	u32 static_rtt;
	u32 fraction;
	u8  rate_eval:1;
        /* For the DCTCP state machine */
        u32 prior_rcv_nxt;
        u32 ce_state;
};

/* Module parameters */
/* lgcc_alpha_16 = alpha << 16 = 0.05 * 2^16 */
static unsigned int lgcc_alpha_16 __read_mostly = 3277;
module_param(lgcc_alpha_16, uint, 0644);
MODULE_PARM_DESC(lgcc_alpha_16, "scaled alpha");

static unsigned int thresh_16 __read_mostly = 52429; // ~0.8 << 16
module_param(thresh_16, uint, 0644);
MODULE_PARM_DESC(thresh_16, "scaled thresh");

/* End of Module parameters */

int sysctl_lgcc_max_rate[1] __read_mostly;	    /* min/default/max */
int sysctl_lgcc_min_rtt[1] __read_mostly;	    /* unit is microseconds (us) */
int sysctl_lgcc_static_rtt[1] __read_mostly;	    /* boolean */

static void lgcc_reset(const struct tcp_sock *tp, struct lgcc *ca)
{
	ca->next_seq = tp->snd_nxt;

	ca->old_delivered = tp->delivered;
	ca->old_delivered_ce = tp->delivered_ce;
}

static void tcp_lgcc_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	int max_rate;
	u64 max_rateS;

	if ((sk->sk_state == TCP_LISTEN || sk->sk_state == TCP_CLOSE)
                                        || 1) {
                                        /* || (tp->ecn_flags & TCP_ECN_OK)) { */
                                        /* XXX: temorary hacked fix! FIXME --Martin */
		struct lgcc *ca = inet_csk_ca(sk);
		max_rate = sysctl_lgcc_max_rate[0];
		max_rateS = 0ULL;

		max_rate *= 125U; // * 1000 / 8
		if (max_rate)
			ca->mrate = (u32)(max_rate);
		if (!ca->mrate)
			ca->mrate = 1250000U; //HERE


		max_rateS = (u64)(ca->mrate);
		max_rateS <<= LGCC_SHIFT;
		ca->max_rateS = max_rateS;

		ca->exp_rate  = (u64)(ca->mrate * 3277U); // *= 0.05 << LGCC_SHIFT
		ca->rate_eval = 0;
		ca->rate      = 65536ULL;

		/* ca->minRTT    = 1U<<20; /1* reference of minRTT ever seen ~1s *1/ */
		ca->minRTT    = sysctl_lgcc_min_rtt[0];
		ca->fraction  = 0U;

                /* If false, update min RTT dynamically with measurements from the TCP stack */
		ca->static_rtt = sysctl_lgcc_static_rtt[0];

		/* Set the "previous" control loop rate to be the maximum possible value. This is to ensure we won't do rate calculations based off it, when not set by a LGCC router, since LGCC's rate algorithm does a `min(rate_prev_loop, ...)`. */
		ca->rate_prev_loop_router_updated = ULLONG_MAX;
		ca->rate_prev_loop_ack_updated = ULLONG_MAX;

		/* Needed for the DCTCP state machine */
		ca->prior_rcv_nxt = tp->rcv_nxt;

		lgcc_reset(tp, ca);

		return;
	}
}

/* Calculate the initial rate of the flow in bytes/mSec
 * rate = cwnd * mss / rtt_ms
 */
static void lgcc_init_rate(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct lgcc *ca = inet_csk_ca(sk);

	u64 init_rate = (u64)(tp->snd_cwnd * tp->mss_cache * 1000);
	init_rate <<= LGCC_SHIFT; // scale the value with LGCC_SHIFT bits
	do_div(init_rate, ca->minRTT);

	ca->rate_prev_loop_router_updated = ULLONG_MAX;
	ca->rate_prev_loop_ack_updated = ULLONG_MAX;

	ca->rate = init_rate;
	ca->rate_eval = 1;
}

static void lgcc_update_pacing_rate(struct sock *sk)
{
	struct lgcc *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	u64 rate;

	/* Set `sk_pacing_rate` to 100 % of current rate (mss * cwnd / rtt) */
	rate = (u64)tp->mss_cache * ((USEC_PER_SEC / 100) << 3);
	rate *= 100U;    /* set to 100 % */
	rate *= max(tp->snd_cwnd, tp->packets_out);

        /* For the RTT we have two options. I have tried both, and results are
	 * about the same:
         * (1) Use the innate TCP stack's calculated smoothed out RTT: */
	if (likely(tp->srtt_us))
		do_div(rate, tp->srtt_us);
	/* (2) use the configured sysctl setting ... Assuming minimum RTT is a
         *     substitute for mean RTT, which might be a bit iffy: */
        /* do_div(rate, ca->minRTT); */

	/* We can also try to not exceed the maximum configured LGC(C) rate. I
         * tried this with no noticable benefit: */
	/* rate = min(rate, ca->mrate * 1000); */

	/* WRITE_ONCE() is needed because sch_fq fetches sk_pacing_rate
	 * without any lock. We want to make sure compiler wont store
	 * intermediate values in this location.
	 */
	WRITE_ONCE(sk->sk_pacing_rate, min_t(u64, rate, sk->sk_max_pacing_rate));
}

static void lgcc_update_rate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgcc *ca = inet_csk_ca(sk);
	u64 rate = ca->rate;
	u64 tmprate = ca->rate;
	u64 new_rate = 0ULL;
	s64 gr_rate_gradient = 1LL;
	u32 fraction = 0U, gr;

	u32 delivered_ce = tp->delivered_ce - ca->old_delivered_ce;
	u32 delivered = tp->delivered - ca->old_delivered;
	delivered_ce <<= LGCC_SHIFT;
	delivered_ce /= max(delivered, 1U);

	if (delivered_ce >= thresh_16)
		fraction = (ONE - lgcc_alpha_16) * ca->fraction + (lgcc_alpha_16 * delivered_ce);
	else
		fraction = (ONE - lgcc_alpha_16) * ca->fraction;

	ca->fraction = (fraction >> LGCC_SHIFT);
	if (ca->fraction >= ONE)
		ca->fraction = 65470U; // 0.999 x ONE

	/* At this point, we have a ca->fraction = [0,1) << LGCC_SHIFT */

	/* Calculate gradient

	 *            - log2(rate/max_rate)    -log2(1-fraction)
	 * gradient = --------------------- - ------------------
	 *                 log2(phi1)             log2(phi2)
	 */

	if (!ca->mrate) /* `mrate` is in bytes per millisecond */
		ca->mrate = 1250000U; // FIXME; Reset the rate value to 10Gbps
	/* do_div(tmprate, ca->mrate); */

	/* Use the most congested signal, i.e the one with the lowest advertised rate */
	u64 rate_prev_loop = min(ca->rate_prev_loop_router_updated, ca->rate_prev_loop_ack_updated);
	rate_prev_loop >>= LGCC_SHIFT;
	/* Note to future Martin: I'm *very* certain the shift above is in the
	 * correct direction! --Martin */

	do_div(tmprate, min(rate_prev_loop, ca->mrate));

	u32 first_term = lgc_log_lut_lookup((u32)tmprate);
	u32 second_term = lgc_log_lut_lookup((u32)(65536U - ca->fraction));

	s32 gradient = first_term - second_term;

	gr = lgc_pow_lut_lookup(delivered_ce); /* LGCC_SHIFT scaled */

	gr_rate_gradient *= gr;
	gr_rate_gradient *= rate;	/* rate: bpms << LGCC_SHIFT */
	gr_rate_gradient >>= LGCC_SHIFT;	/* back to 16-bit scaled */
	gr_rate_gradient *= gradient;

	new_rate = (u64)((rate << LGCC_SHIFT) + gr_rate_gradient);
	new_rate >>= LGCC_SHIFT;

	/* new rate shouldn't increase more than twice */
	if (new_rate > (rate << 1))
		rate <<= 1;
	else if (new_rate == 0)
		rate = 65536U;
	else
		rate = new_rate;

	/* Check if the new rate exceeds the link capacity */
	if (rate > ca->max_rateS)
		rate = ca->max_rateS;

	/* lgcc_rate can be read from lgcc_get_info() without
	 * synchro, so we ask compiler to not use rate
	 * as a temporary variable in prior operations.
	 */
	WRITE_ONCE(ca->rate, rate);

        /* printk(KERN_DEBUG "LGCC: lgcc_update_rate: 0x%llx\n", ca->rate); */
}

/* Calculate cwnd based on current rate and minRTT
 * cwnd = rate * minRT / mss
 */
static void lgcc_set_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgcc *ca = inet_csk_ca(sk);

	u64 target = (u64)(ca->rate * ca->minRTT);
	target >>= LGCC_SHIFT;
	do_div(target, tp->mss_cache * 1000);

	tp->snd_cwnd = max_t(u32, (u32)target + 1, 2U);

	if (tp->snd_cwnd > tp->snd_cwnd_clamp)
		tp->snd_cwnd = tp->snd_cwnd_clamp;

	target = (u64)(tp->snd_cwnd * tp->mss_cache * 1000);
	target <<= LGCC_SHIFT;
	do_div(target, ca->minRTT);

	WRITE_ONCE(ca->rate, target);
}

/* Get the rate of the last rate, as advertised in the last received ACK. This
 * is executed every time we receive an ACK. */
void tcp_lgcc_get_rate_prev_loop(struct sock *sk, u32 flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgcc *ca = inet_csk_ca(sk);

        /* TODO: should this be dampened? (Peymant's code multiplies by 0.8, I think.) */
	WRITE_ONCE(ca->rate_prev_loop_ack_updated, tp->rx_opt.lgcc_rate);
        /* if (get_random_u32() % 1000 == 0) */
        /*         printk(KERN_DEBUG "LGCC: recieved rate from ACK: 0x%llx\n", ca->rate_prev_loop_ack_updated); */
}

/* Parse TCP option, and store the advertized rate in the CA state. Called by the LGCC router (PEP-DNA). */
void tcp_lgcc_set_rate_prev_loop(struct tcp_sock *from, struct sock *to)
{
        struct lgcc *ca = inet_csk_ca(to);

        /* I suspect this is wrong: */
        /* WRITE_ONCE(ca->rate_prev_loop, from->rx_opt.lgcc_rate); */

        /* This might be right, though: */
        WRITE_ONCE(ca->rate_prev_loop_router_updated, ((struct lgcc *)(from->inet_conn.icsk_ca_priv))->rate);

        /* if (get_random_u32() % 1000 == 0) */
        /*         printk(KERN_DEBUG "LGCC: setting rate_prev_loop_router_updated: 0x%llx\n", ((struct lgcc *)(from->inet_conn.icsk_ca_priv))->rate); */
}
EXPORT_SYMBOL(tcp_lgcc_set_rate_prev_loop);

/* Send the rate we would like to advertise (for the LGCC TCP option). Called by the TCP (output) stack. */
u64 tcp_lgcc_get_rate(struct tcp_sock *tp)
{
        /* if (get_random_u32() % 1000 == 0) */
        /*         printk(KERN_DEBUG "LGCC: advertising in ACK: 0x%llx\n", ((struct lgcc *)(tp->inet_conn.icsk_ca_priv))->rate_prev_loop_router_updated); */
        /* TODO: this is super ugly. Does there exist an interface to cast
         * this correctly? */
        return ((struct lgcc *)(tp->inet_conn.icsk_ca_priv))->rate_prev_loop_router_updated;
}
EXPORT_SYMBOL(tcp_lgcc_get_rate);

/* Copied from DCTCP's implementation, `dctcp_cwnd_event()`, with minor
 * modifications. We don't need PLB, and we want to use LGCC state variables. */
__bpf_kfunc static void lgcc_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct lgcc *ca = inet_csk_ca(sk);

	switch (ev) {
	case CA_EVENT_ECN_IS_CE:
	case CA_EVENT_ECN_NO_CE:
		dctcp_ece_ack_update(sk, ev, &ca->prior_rcv_nxt, &ca->ce_state);
		break;
	/* case CA_EVENT_LOSS: */
		/* tcp_plb_update_state_upon_rto(sk, &ca->plb); */
		/* dctcp_react_to_loss(sk); */
		/* break; */
	/* case CA_EVENT_TX_START: */
		/* tcp_plb_check_rehash(sk, &ca->plb); /1* Maybe rehash when inflight is 0 *1/ */
		/* break; */
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
	struct lgcc *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	return max(tcp_snd_cwnd(tp), 2U);
}

static void tcp_lgcc_main(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgcc *ca = inet_csk_ca(sk);

	/* Expired RTT */
	if (!before(tp->snd_una, ca->next_seq)) {

                if (ca->static_rtt != 0)
                        ca->minRTT = min_not_zero(tcp_min_rtt(tp), ca->minRTT);
		/* The above may be disabled, since the use of a PEP in LGCC mess with the
		 * built-in min-RTT calculation. We have to assume the sysctl setting
		 * is correct instead.   --Martin */

		if (unlikely(!ca->rate_eval))
			lgcc_init_rate(sk);

		lgcc_update_rate(sk);
		lgcc_set_cwnd(sk);
                /* lgcc_update_pacing_rate(sk); */
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
                info->lgcc.lgcc_rate = 65536000 >> LGCC_SHIFT;
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
	.init		= tcp_lgcc_init,
	.cong_control	= tcp_lgcc_main,
	.cwnd_event	= lgcc_cwnd_event,
	.in_ack_event	= tcp_lgcc_get_rate_prev_loop,
	.ssthresh	= tcp_lgcc_ssthresh,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.get_info	= tcp_lgcc_get_info,
	.flags		= TCP_CONG_NEEDS_ECN,
	.owner		= THIS_MODULE,
	.name		= "lgcc",
};

static int __init lgcc_register(void)
{
	BUILD_BUG_ON(sizeof(struct lgcc) > ICSK_CA_PRIV_SIZE);
	lgcc_register_sysctl();
	sysctl_lgcc_max_rate[0] = 1000;
	sysctl_lgcc_min_rtt[0] = 1U<<20;   /* ~1s */
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
