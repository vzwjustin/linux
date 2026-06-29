// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * printk_safe.c - Safe printk for printk-deadlock-prone contexts
 */

#include <linux/preempt.h>
#include <linux/kdb.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/printk.h>
#include <linux/kprobes.h>

#include "internal.h"

/* Context where printk messages are never suppressed */
static atomic_t force_con;

void printk_force_console_inc(void)
{
	atomic_inc(&force_con);
}

void printk_force_console_dec(void)
{
	atomic_dec(&force_con);
}

bool printk_force_console_read(void)
{
	return atomic_read(&force_con);
}

static DEFINE_PER_CPU(int, printk_context);

void printk_context_inc(void)
{
	this_cpu_inc(printk_context);
}

void printk_context_dec(void)
{
	this_cpu_dec(printk_context);
}

int printk_context_read(void)
{
	return this_cpu_read(printk_context);
}

void printk_cant_migrate(void)
{
	cant_migrate();
}

bool printk_force_legacy_kthread(void)
{
	return force_legacy_kthread();
}

bool printk_in_nmi(void)
{
	return in_nmi();
}

bool printk_cpu_sync_owner(void)
{
	return is_printk_cpu_sync_owner();
}

asmlinkage int vprintk(const char *fmt, va_list args)
{
#ifdef CONFIG_KGDB_KDB
	/* Allow to pass printk() to kdb but avoid a recursion. */
	if (unlikely(kdb_trap_printk && kdb_printf_cpu < 0))
		return vkdb_printf(KDB_MSGSRC_PRINTK, fmt, args);
#endif
	return vprintk_default(fmt, args);
}
EXPORT_SYMBOL(vprintk);
