// SPDX-License-Identifier: GPL-2.0+
/*
 * debugfs file to track time spent in suspend
 *
 * Copyright (c) 2011, Google, Inc.
 */

#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/suspend.h>
#include <linux/time.h>

#include "timekeeping_internal.h"

#define NUM_BINS 32

/* Incremented every time mg_floor is updated */
DEFINE_PER_CPU(unsigned long, timekeeping_mg_floor_swaps);

static unsigned int sleep_time_bin[NUM_BINS] = {0};

void tk_debug_seq_header(struct seq_file *s)
{
	seq_puts(s, "      time (secs)        count\n");
	seq_puts(s, "------------------------------\n");
}

void tk_debug_seq_bin(struct seq_file *s, unsigned int bin, unsigned int count)
{
	seq_printf(s, "%10u - %-10u %4u\n",
		   bin ? 1 << (bin - 1) : 0, 1 << bin, count);
}

unsigned int tk_debug_sleep_time_bin(unsigned int bin)
{
	return sleep_time_bin[bin];
}

void tk_debug_sleep_time_bin_inc(unsigned int bin)
{
	sleep_time_bin[bin]++;
}

int tk_debug_sleep_time_bin_for_seconds(time64_t seconds)
{
	return min(fls(seconds), NUM_BINS - 1);
}

void tk_debug_print_sleep_time(const struct timespec64 *t)
{
	pm_deferred_pr_dbg("Timekeeping suspended for %lld.%03lu seconds\n",
			   (s64)t->tv_sec, t->tv_nsec / NSEC_PER_MSEC);
}

unsigned long tk_debug_mg_floor_swaps_sum(void)
{
	unsigned long sum = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		sum += data_race(per_cpu(timekeeping_mg_floor_swaps, cpu));

	return sum;
}

int tk_debug_sleep_time_show_rs(struct seq_file *s);

static int tk_debug_sleep_time_show(struct seq_file *s, void *data)
{
	return tk_debug_sleep_time_show_rs(s);
}
DEFINE_SHOW_ATTRIBUTE(tk_debug_sleep_time);

static int __init tk_debug_sleep_time_init(void)
{
	debugfs_create_file("sleep_time", 0444, NULL, NULL,
			    &tk_debug_sleep_time_fops);
	return 0;
}
late_initcall(tk_debug_sleep_time_init);

void tk_debug_account_sleep_time_rs(const struct timespec64 *t);

void tk_debug_account_sleep_time(const struct timespec64 *t)
{
	tk_debug_account_sleep_time_rs(t);
}

unsigned long timekeeping_get_mg_floor_swaps_rs(void);

unsigned long timekeeping_get_mg_floor_swaps(void)
{
	return timekeeping_get_mg_floor_swaps_rs();
}
