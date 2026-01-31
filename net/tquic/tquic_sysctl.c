// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Sysctl Interface for Tuning
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides sysctl parameters for tuning TQUIC WAN bonding behavior.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <net/netns/tquic.h>
#include <net/tquic.h>

/* Global tunables */
static int tquic_enabled = 1;
static int tquic_default_bond_mode = TQUIC_BOND_MODE_AGGREGATE;
static int tquic_max_paths = TQUIC_MAX_PATHS;
static int tquic_reorder_window = 64;
static int tquic_probe_interval = 1000;  /* ms */
static int tquic_failover_timeout = 3000; /* ms */
static int tquic_idle_timeout = 30000;   /* ms */
static int tquic_max_data_mb = 1;        /* MB */
static int tquic_max_stream_data_kb = 256; /* KB */
static int tquic_ack_delay = 25;         /* ms */

/* RTT-related tunables */
static int tquic_initial_rtt = 100;      /* ms */
static int tquic_min_rtt = 1;            /* ms */

/* Congestion control tunables */
static int tquic_initial_cwnd = 10;      /* packets */
static int tquic_min_cwnd = 2;           /* packets */

/* Scheduler tunables */
static char tquic_scheduler[16] = "minrtt";
static char tquic_congestion[16] = "cubic";

/* Debug tunables */
static int tquic_debug_level;

/* Forward declarations for scheduler API */
struct tquic_sched_ops;
struct tquic_sched_ops *tquic_sched_find(const char *name);

/*
 * Per-netns scheduler sysctl handler
 *
 * Handles reading/writing net.tquic.scheduler which sets the default
 * scheduler for new connections in this network namespace.
 *
 * On read: Returns current default scheduler name
 * On write: Validates scheduler exists and sets as default
 */
static int proc_tquic_scheduler(struct ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	char name[NETNS_TQUIC_SCHED_NAME_MAX];
	struct ctl_table tmp_table;
	int ret;

	if (!write) {
		/* Read current default scheduler for this netns */
		const char *current_name;

		rcu_read_lock();
		if (net->tquic.default_scheduler)
			current_name = net->tquic.default_scheduler->name;
		else
			current_name = "aggregate";
		rcu_read_unlock();

		strscpy(name, current_name, sizeof(name));

		/* Use temporary table pointing to our local buffer */
		memset(&tmp_table, 0, sizeof(tmp_table));
		tmp_table.procname = table->procname;
		tmp_table.data = name;
		tmp_table.maxlen = sizeof(name);
		tmp_table.mode = table->mode;

		return proc_dostring(&tmp_table, write, buffer, lenp, ppos);
	}

	/* Write: get new scheduler name from user */
	strscpy(name, net->tquic.sched_name, sizeof(name));

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.procname = table->procname;
	tmp_table.data = name;
	tmp_table.maxlen = sizeof(name);
	tmp_table.mode = table->mode;

	ret = proc_dostring(&tmp_table, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	/* Validate scheduler exists */
	rcu_read_lock();
	if (!tquic_sched_find(name)) {
		rcu_read_unlock();
		pr_warn("tquic: unknown scheduler '%s'\n", name);
		return -ENOENT;
	}
	rcu_read_unlock();

	/* Set per-netns default scheduler */
	ret = tquic_sched_set_default(net, name);
	if (ret) {
		pr_warn("tquic: failed to set scheduler '%s': %d\n", name, ret);
		return ret;
	}

	pr_debug("tquic: netns scheduler set to '%s'\n", name);
	return 0;
}

/* Legacy global sysctl handler (for compatibility) */
static int tquic_sysctl_scheduler(struct ctl_table *table, int write,
				  void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dostring(table, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	/* Validate and set global scheduler (legacy) */
	rcu_read_lock();
	if (!tquic_sched_find(tquic_scheduler)) {
		rcu_read_unlock();
		pr_warn("tquic: unknown scheduler '%s'\n", tquic_scheduler);
		return -ENOENT;
	}
	rcu_read_unlock();

	/* Also set for init_net as the per-netns default */
	ret = tquic_sched_set_default(&init_net, tquic_scheduler);
	if (ret)
		pr_warn("tquic: failed to set default scheduler '%s'\n",
			tquic_scheduler);

	return 0;
}

static int tquic_sysctl_bond_mode(struct ctl_table *table, int write,
				  void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	if (tquic_default_bond_mode > TQUIC_BOND_MODE_ECF) {
		tquic_default_bond_mode = TQUIC_BOND_MODE_AGGREGATE;
		return -EINVAL;
	}

	return 0;
}

/* Min/max values for integer tunables */
static int zero;
static int one = 1;
static int max_paths = TQUIC_MAX_PATHS;
static int max_reorder = 1024;
static int max_timeout = 60000;
static int max_rtt = 10000;
static int max_cwnd = 10000;
static int max_bond_mode = TQUIC_BOND_MODE_ECF;
static int max_data = 1024;    /* MB */
static int max_ack_delay = 1000;

/* Sysctl table */
static struct ctl_table tquic_sysctl_table[] = {
	{
		.procname	= "enabled",
		.data		= &tquic_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "default_bond_mode",
		.data		= &tquic_default_bond_mode,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= tquic_sysctl_bond_mode,
		.extra1		= &zero,
		.extra2		= &max_bond_mode,
	},
	{
		.procname	= "max_paths",
		.data		= &tquic_max_paths,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_paths,
	},
	{
		.procname	= "reorder_window",
		.data		= &tquic_reorder_window,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_reorder,
	},
	{
		.procname	= "probe_interval_ms",
		.data		= &tquic_probe_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_timeout,
	},
	{
		.procname	= "failover_timeout_ms",
		.data		= &tquic_failover_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_timeout,
	},
	{
		.procname	= "idle_timeout_ms",
		.data		= &tquic_idle_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_timeout,
	},
	{
		.procname	= "initial_rtt_ms",
		.data		= &tquic_initial_rtt,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_rtt,
	},
	{
		.procname	= "min_rtt_ms",
		.data		= &tquic_min_rtt,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_rtt,
	},
	{
		.procname	= "initial_cwnd_packets",
		.data		= &tquic_initial_cwnd,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_cwnd,
	},
	{
		.procname	= "min_cwnd_packets",
		.data		= &tquic_min_cwnd,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_cwnd,
	},
	{
		.procname	= "max_data_mb",
		.data		= &tquic_max_data_mb,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_data,
	},
	{
		.procname	= "max_stream_data_kb",
		.data		= &tquic_max_stream_data_kb,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_data,
	},
	{
		.procname	= "max_ack_delay_ms",
		.data		= &tquic_ack_delay,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &max_ack_delay,
	},
	{
		.procname	= "scheduler",
		.data		= tquic_scheduler,
		.maxlen		= sizeof(tquic_scheduler),
		.mode		= 0644,
		.proc_handler	= proc_tquic_scheduler,
	},
	{
		.procname	= "congestion",
		.data		= tquic_congestion,
		.maxlen		= sizeof(tquic_congestion),
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "debug_level",
		.data		= &tquic_debug_level,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static struct ctl_table_header *tquic_sysctl_header;

/* Accessor functions for other modules */
int tquic_sysctl_get_bond_mode(void)
{
	return tquic_default_bond_mode;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_bond_mode);

int tquic_sysctl_get_max_paths(void)
{
	return tquic_max_paths;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_max_paths);

int tquic_sysctl_get_reorder_window(void)
{
	return tquic_reorder_window;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_reorder_window);

int tquic_sysctl_get_probe_interval(void)
{
	return tquic_probe_interval;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_probe_interval);

int tquic_sysctl_get_failover_timeout(void)
{
	return tquic_failover_timeout;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_failover_timeout);

int tquic_sysctl_get_idle_timeout(void)
{
	return tquic_idle_timeout;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_idle_timeout);

int tquic_sysctl_get_initial_rtt(void)
{
	return tquic_initial_rtt;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_initial_rtt);

int tquic_sysctl_get_initial_cwnd(void)
{
	return tquic_initial_cwnd;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_initial_cwnd);

int tquic_sysctl_get_debug_level(void)
{
	return tquic_debug_level;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_debug_level);

const char *tquic_sysctl_get_scheduler(void)
{
	return tquic_scheduler;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_scheduler);

const char *tquic_sysctl_get_congestion(void)
{
	return tquic_congestion;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_congestion);

int __init tquic_sysctl_init(void)
{
	tquic_sysctl_header = register_net_sysctl(&init_net, "net/tquic",
						  tquic_sysctl_table);
	if (!tquic_sysctl_header)
		return -ENOMEM;

	pr_info("tquic: sysctl interface registered at /proc/sys/net/tquic/\n");
	return 0;
}

void __exit tquic_sysctl_exit(void)
{
	if (tquic_sysctl_header)
		unregister_net_sysctl_table(tquic_sysctl_header);
}
