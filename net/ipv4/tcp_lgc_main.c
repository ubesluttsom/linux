// SPDX-License-Identifier: GPL-2.0-or-later
/* Logistic Growth Control (LGC) congestion control.
 *
 * https://www.mn.uio.no/ifi/english/research/projects/ocarina/
 *
 * This is an implementation of LGC-ShQ, a new ECN-based congestion control
 * mechanism for datacenters. LGC-ShQ relies on ECN feedback from a Shadow
 * Queue, and it uses ECN not only to decrease the rate, but it also increases
 * the rate in relation to this signal.  Real-life tests in a Linux testbed show
 * that LGC-ShQ keeps the real queue at low levels while achieving good link
 * utilization and fairness.
 *
 * The algorithm is described in detail in the following paper:
 *
 * Initial prototype on OMNet++ by Peyman Teymoori
 *
 * Author:
 *
 *	Kr1stj0n C1k0 <kristjoc@ifi.uio.no>
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include "tcp_lgc.h"
#include "tcp_dctcp.h"
#include <linux/printk.h> /* FIXME: remove. For LGCC debugging. */
#include <linux/random.h>   /* FIXME: remove. For LGCC debugging. */

#define LGC_SHIFT	16
#define ONE		(1U<<16)
#define THRESSH		52429U
#define BW_GAIN		((120U<<8)/100)

struct lgc {
	u32 old_delivered;
	u32 old_delivered_ce;
	u32 next_seq;
	u64 rate;
	u64 rate_prev_loop;
	u64 max_rateS;
	u32 mrate;
	u64 exp_rate;
	u32 minRTT;
	u32 fraction;
	u8  rate_eval:1;
        /* For the DCTCP state machine */
        u32 prior_rcv_nxt;
        u32 ce_state;
};

/* Module parameters */
/* lgc_alpha_16 = alpha << 16 = 0.05 * 2^16 */
static unsigned int lgc_alpha_16 __read_mostly = 3277;
module_param(lgc_alpha_16, uint, 0644);
MODULE_PARM_DESC(lgc_alpha_16, "scaled alpha");

static unsigned int thresh_16 __read_mostly = 52429; // ~0.8 << 16
module_param(thresh_16, uint, 0644);
MODULE_PARM_DESC(thresh_16, "scaled thresh");

/* End of Module parameters */

int sysctl_lgc_max_rate[1] __read_mostly;	    /* min/default/max */
int sysctl_lgc_min_rtt[1] __read_mostly;	    /* unit is microseconds (us) */

static struct tcp_congestion_ops lgc_reno;

static void lgc_reset(const struct tcp_sock *tp, struct lgc *ca)
{
	ca->next_seq = tp->snd_nxt;

	ca->old_delivered = tp->delivered;
	ca->old_delivered_ce = tp->delivered_ce;
}

static void tcp_lgc_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	int max_rate;
	u64 max_rateS;

	if ((sk->sk_state == TCP_LISTEN || sk->sk_state == TCP_CLOSE)
                                        || 1) {
                                        /* || (tp->ecn_flags & TCP_ECN_OK)) { */
                                        /* XXX: temorary hacked fix! FIXME --Martin */
		struct lgc *ca = inet_csk_ca(sk);
		max_rate = sysctl_lgc_max_rate[0];
		max_rateS = 0ULL;

		max_rate *= 125U; // * 1000 / 8
		if (max_rate)
			ca->mrate = (u32)(max_rate);
		if (!ca->mrate)
			ca->mrate = 1250000U; //HERE


		max_rateS = (u64)(ca->mrate);
		max_rateS <<= LGC_SHIFT;
		ca->max_rateS = max_rateS;

		ca->exp_rate  = (u64)(ca->mrate * 3277U); // *= 0.05 << LGC_SHIFT
		ca->rate_eval = 0;
		ca->rate      = 65536ULL;
		/* ca->minRTT    = 1U<<20; /1* reference of minRTT ever seen ~1s *1/ */
		ca->minRTT    = sysctl_lgc_min_rtt[0];
		ca->fraction  = 0U;

		/* Needed for the DCTCP state machine */
		ca->prior_rcv_nxt = tp->rcv_nxt;

		lgc_reset(tp, ca);

		return;
	}

	/* No ECN support? Fall back to Reno. Also need to clear
	 * ECT from sk since it is set during 3WHS for LGC.
	 */
	inet_csk(sk)->icsk_ca_ops = &lgc_reno;
	INET_ECN_dontxmit(sk);
}

/* Calculate the initial rate of the flow in bytes/mSec
 * rate = cwnd * mss / rtt_ms
 */
static void lgc_init_rate(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);

	u64 init_rate = (u64)(tp->snd_cwnd * tp->mss_cache * 1000);
	init_rate <<= LGC_SHIFT; // scale the value with LGC_SHIFT bits
	do_div(init_rate, ca->minRTT);

	ca->rate = init_rate;
	ca->rate_eval = 1;
}

static void lgc_update_pacing_rate(struct sock *sk)
{
	struct lgc *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	u64 rate;

	/* Set `sk_pacing_rate` to 100 % of current rate (mss * cwnd / rtt) */
	rate = (u64)tp->mss_cache * ((USEC_PER_SEC / 100) << 3);
	rate *= 100U;
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

static void lgc_update_rate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);
	u64 rate = ca->rate;
	u64 tmprate = ca->rate;
	u64 new_rate = 0ULL;
	s64 gr_rate_gradient = 1LL;
	u32 fraction = 0U, gr;

	u32 delivered_ce = tp->delivered_ce - ca->old_delivered_ce;
	u32 delivered = tp->delivered - ca->old_delivered;
	delivered_ce <<= LGC_SHIFT;
	delivered_ce /= max(delivered, 1U);

	if (delivered_ce >= thresh_16)
		fraction = (ONE - lgc_alpha_16) * ca->fraction + (lgc_alpha_16 * delivered_ce);
	else
		fraction = (ONE - lgc_alpha_16) * ca->fraction;

	ca->fraction = (fraction >> LGC_SHIFT);
	if (ca->fraction >= ONE)
		ca->fraction = 65470U; // 0.999 x ONE

	/* At this point, we have a ca->fraction = [0,1) << LGC_SHIFT */

	/* Calculate gradient

	 *            - log2(rate/max_rate)    -log2(1-fraction)
	 * gradient = --------------------- - ------------------
         *                 log2(phi1)             log2(phi2)
	 */

	if (!ca->mrate) /* `mrate` is in bytes per millisecond */
		ca->mrate = 1250000U; // FIXME; Reset the rate value to 10Gbps
	/* do_div(tmprate, ca->mrate); */
	do_div(tmprate, min(ca->rate_prev_loop >> LGC_SHIFT, ca->mrate));
	/* Note to future Martin: I'm *very* certain the shift above is in the correct direction! --Martin */

	u32 first_term = lgc_log_lut_lookup((u32)tmprate);
	u32 second_term = lgc_log_lut_lookup((u32)(65536U - ca->fraction));

	s32 gradient = first_term - second_term;

	gr = lgc_pow_lut_lookup(delivered_ce); /* LGC_SHIFT scaled */

	/* s32 lgcc_r = (s32)gr; */
	/* if (gr < 12451 && ca->fraction) { */
	/* 	u32 exp = lgc_exp_lut_lookup(ca->fraction); */
	/* 	s64 expRate = (s64)ca->max_rate; */
	/* 	expRate *= exp; */
	/* 	s64 crate = (s64)ca->rate; */
	/* 	s64 delta; */

	/* 	if (expRate > ca->exp_rate && ca->rate < expRate - ca->exp_rate && */
	/* 	    ca->rate < ca->max_rateS) { */
	/* 		delta = expRate - crate; */
	/* 		delta /= ca->max_rate; */
	/* 		lgcc_r = (s32)delta; */
	/* 	} else if (ca->rate > expRate + ca->exp_rate) { */
	/* 		if (gradient < 0) { */
	/* 			delta = crate - expRate; */
	/* 			delta /= ca->max_rate; */
	/* 			lgcc_r = (s32)delta; */
	/* 		} */
	/* 	} else if ( expRate < ca->max_rateS) */
	/* 			lgcc_r = (s32)(984); */
	/* } */

	gr_rate_gradient *= gr;
	gr_rate_gradient *= rate;	/* rate: bpms << LGC_SHIFT */
	gr_rate_gradient >>= LGC_SHIFT;	/* back to 16-bit scaled */
	gr_rate_gradient *= gradient;

	new_rate = (u64)((rate << LGC_SHIFT) + gr_rate_gradient);
	new_rate >>= LGC_SHIFT;

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

	/* lgc_rate can be read from lgc_get_info() without
	 * synchro, so we ask compiler to not use rate
	 * as a temporary variable in prior operations.
	 */
	WRITE_ONCE(ca->rate, rate);
}

/* Calculate cwnd based on current rate and minRTT
 * cwnd = rate * minRT / mss
 */
static void lgc_set_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);

	u64 target = (u64)(ca->rate * ca->minRTT);
	target >>= LGC_SHIFT;
	do_div(target, tp->mss_cache * 1000);

	tp->snd_cwnd = max_t(u32, (u32)target + 1, 10U);
	/* Add a small gain to avoid truncation in bandwidth - disabled 4 now */
	/* tp->snd_cwnd *= BW_GAIN; */
	/* tp->snd_cwnd >>= LGC_SHIFT; */

	if (tp->snd_cwnd > tp->snd_cwnd_clamp)
		tp->snd_cwnd = tp->snd_cwnd_clamp;

	target = (u64)(tp->snd_cwnd * tp->mss_cache * 1000);
	target <<= LGC_SHIFT;
	do_div(target, ca->minRTT);

	WRITE_ONCE(ca->rate, target);
}

/* Parse TCP option, and store the advertized rate in the CA state. */
void tcp_lgcc_set_rate_prev_loop(struct tcp_sock *from, struct sock *to)
{
        struct lgc *ca = inet_csk_ca(to);
        /* if (get_random_u32() % 300 == 0) */
        /*         printk(KERN_DEBUG "LGCC: setting rate_prev_loop to 0x%llx (random)\n", from->rx_opt.lgcc_rate); */
        WRITE_ONCE(ca->rate_prev_loop, from->rx_opt.lgcc_rate);
}
EXPORT_SYMBOL(tcp_lgcc_set_rate_prev_loop);

/* Send the rate we would like to advertise (for the LGCC TCP option). */
u64 tcp_lgcc_get_rate(struct tcp_sock *tp)
{
        /* TODO: this is super ugly. Does there exist an interface to cast
         * this correctly? */
        return ((struct lgc *)(tp->inet_conn.icsk_ca_priv))->rate;
}
EXPORT_SYMBOL(tcp_lgcc_get_rate);

/* Copied from DCTCP's implementation, `dctcp_cwnd_event()`, with minor
 * modifications. We don't need PLB, and we want to use LGC state variables. */
__bpf_kfunc static void lgc_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct lgc *ca = inet_csk_ca(sk);

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
        lgc_update_rate(sk);
}

static void tcp_lgc_main(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);

	/* Expired RTT */
	if (!before(tp->snd_una, ca->next_seq)) {

		ca->minRTT = min_not_zero(tcp_min_rtt(tp), ca->minRTT);
		/* The above is disabled, since the use of a PEP in LGCC mess with the
                 * built-in min-RTT calculation. We have to assume the sysctl setting
                 * is correct instead.   --Martin */

		if (unlikely(!ca->rate_eval))
			lgc_init_rate(sk);

                /* TODO: My intuition is that this should should only be done by a PEP
                 * router. Therefore I'm commenting this out for now.   --Martin */
                /* tcp_lgcc_set_rate_prev_loop(tp, sk); */
		lgc_update_rate(sk);
		lgc_set_cwnd(sk);
		lgc_reset(tp, ca);
	}
	lgc_update_pacing_rate(sk);
}

static size_t tcp_lgc_get_info(struct sock *sk, u32 ext, int *attr,
			       union tcp_cc_info *info)
{
	const struct lgc *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Fill it also in case of VEGASINFO due to req struct limits.
	 * We can still correctly retrieve it later.
	 */
	if (ext & (1 << (INET_DIAG_LGCINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		memset(&info->lgc, 0, sizeof(info->lgc));
		if (inet_csk(sk)->icsk_ca_ops != &lgc_reno) {
			info->lgc.lgc_enabled = 1;
			info->lgc.lgc_rate = 65536000 >> LGC_SHIFT;
			info->lgc.lgc_ab_ecn = tp->mss_cache *
				      (tp->delivered_ce - ca->old_delivered_ce);
			info->lgc.lgc_ab_tot = tp->mss_cache *
					    (tp->delivered - ca->old_delivered);
		}

		*attr = INET_DIAG_LGCINFO;
		return sizeof(info->lgc);
	}
	return 0;
}

static struct tcp_congestion_ops lgc __read_mostly = {
	.init		= tcp_lgc_init,
	.cong_control	= tcp_lgc_main,
	.cwnd_event	= lgc_cwnd_event,
	.ssthresh	= tcp_reno_ssthresh,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.get_info	= tcp_lgc_get_info,
	.flags		= TCP_CONG_NEEDS_ECN,
	.owner		= THIS_MODULE,
	.name		= "lgc",
};

static struct tcp_congestion_ops lgc_reno __read_mostly = {
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.get_info	= tcp_lgc_get_info,
	.owner		= THIS_MODULE,
	.name		= "lgc-reno",
};

static int __init lgc_register(void)
{
	BUILD_BUG_ON(sizeof(struct lgc) > ICSK_CA_PRIV_SIZE);
	lgc_register_sysctl();
	sysctl_lgc_max_rate[0] = 1000;
	sysctl_lgc_min_rtt[0] = 1U<<20;   /* ~1s */
	return tcp_register_congestion_control(&lgc);
}

static void __exit lgc_unregister(void)
{
	tcp_unregister_congestion_control(&lgc);
	lgc_unregister_sysctl();
}

module_init(lgc_register);
module_exit(lgc_unregister);

MODULE_AUTHOR("Kr1stj0n C1k0 <kristjoc@ifi.uio.no>");
MODULE_LICENSE("GPL");
MODULE_VERSION("2.0");
MODULE_DESCRIPTION("Logistic Growth Congestion Control (LGC)");
