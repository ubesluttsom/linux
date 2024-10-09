#ifndef _TCP_LGCC_H_
#define _TCP_LGCC_H_

#include <linux/types.h>
#include <net/net_namespace.h>
#include <net/tcp.h>

extern int sysctl_lgcc_max_rate[1] __read_mostly;
extern int sysctl_lgcc_min_rtt[1] __read_mostly;

inline int lgcc_register_sysctl(void);
inline void lgcc_unregister_sysctl(void);

u64 tcp_lgcc_get_rate(struct tcp_sock *tp);
void tcp_lgcc_set_rate_prev_loop(struct tcp_sock *from, struct sock *to);

#endif
