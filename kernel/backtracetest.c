// SPDX-License-Identifier: GPL-2.0-only
/*
 * Simple stack backtrace regression test module
 *
 * (C) Copyright 2008 Intel Corporation
 * Author: Arjan van de Ven <arjan@linux.intel.com>
 */

#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>

void backtrace_test_info(const char *msg)
{
	pr_info("%s", msg);
}

void backtrace_test_dump_stack(void)
{
	dump_stack();
}

static void backtrace_test_bh_workfn(struct work_struct *work)
{
	dump_stack();
}

static DECLARE_WORK(backtrace_bh_work, &backtrace_test_bh_workfn);

void backtrace_test_bh_queue_flush(void)
{
	queue_work(system_bh_wq, &backtrace_bh_work);
	flush_work(&backtrace_bh_work);
}

#ifdef CONFIG_STACKTRACE
void backtrace_test_saved_rs(void)
{
	unsigned long entries[8];
	unsigned int nr_entries;

	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
	stack_trace_print(entries, nr_entries, 0);
}
#else
void backtrace_test_saved_rs(void)
{
	pr_info("Saved backtrace test skipped.\n");
}
#endif

int backtrace_regression_test_rs(void);

static int backtrace_regression_test(void)
{
	return backtrace_regression_test_rs();
}

static void exitf(void)
{
}

module_init(backtrace_regression_test);
module_exit(exitf);
MODULE_DESCRIPTION("Simple stack backtrace regression test module");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arjan van de Ven <arjan@linux.intel.com>");
