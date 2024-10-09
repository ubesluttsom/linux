/*
 *  net/ipv4/tcp_lgcc_sysctl.c: sysctl interface to LGCC module
 */

#include "tcp_lgcc.h"

#include <net/net_namespace.h>
#include <linux/sysctl.h>

static struct ctl_table_header *lgcc_ctl_hdr;

static struct ctl_table lgcc_table[] = {
        {
                .procname     = "lgcc_max_rate",
                .data	      = &sysctl_lgcc_max_rate,
                .maxlen	      = sizeof(sysctl_lgcc_max_rate),
                .mode	      = 0644,
                .proc_handler = proc_dointvec,
        },
        {
                .procname     = "lgcc_min_rtt",
                .data	      = &sysctl_lgcc_min_rtt,
                .maxlen	      = sizeof(sysctl_lgcc_min_rtt),
                .mode	      = 0644,
                .proc_handler = proc_dointvec,
        },
};

inline int lgcc_register_sysctl(void)
{
        lgcc_ctl_hdr = register_net_sysctl(&init_net, "net/ipv4/lgcc", lgcc_table);
        if (lgcc_ctl_hdr == NULL)
                return -ENOMEM;

        return 0;
}

inline void lgcc_unregister_sysctl(void)
{
        unregister_net_sysctl_table(lgcc_ctl_hdr);
}
