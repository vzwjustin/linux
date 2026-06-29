// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2011 Google, Inc.
 *
 * Author:
 *	Colin Cross <ccross@android.com>
 */

#include <linux/kernel.h>
#include <linux/cpu_pm.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/spinlock.h>
#include <linux/syscore_ops.h>

/*
 * atomic_notifiers use a spinlock_t, which can block under PREEMPT_RT.
 * Notifications for cpu_pm will be issued by the idle task itself, which can
 * never block, IOW it requires using a raw_spinlock_t.
 */
static struct {
	struct raw_notifier_head chain;
	raw_spinlock_t lock;
} cpu_pm_notifier = {
	.chain = RAW_NOTIFIER_INIT(cpu_pm_notifier.chain),
	.lock  = __RAW_SPIN_LOCK_UNLOCKED(cpu_pm_notifier.lock),
};

/* C wrappers for notifier primitives callable from Rust */
int cpmpm_chain_register(struct notifier_block *nb)
{
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&cpu_pm_notifier.lock, flags);
	ret = raw_notifier_chain_register(&cpu_pm_notifier.chain, nb);
	raw_spin_unlock_irqrestore(&cpu_pm_notifier.lock, flags);
	return ret;
}

int cpmpm_chain_unregister(struct notifier_block *nb)
{
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&cpu_pm_notifier.lock, flags);
	ret = raw_notifier_chain_unregister(&cpu_pm_notifier.chain, nb);
	raw_spin_unlock_irqrestore(&cpu_pm_notifier.lock, flags);
	return ret;
}

int cpmpm_notify(unsigned long event)
{
	int ret;

	rcu_read_lock();
	ret = raw_notifier_call_chain(&cpu_pm_notifier.chain, event, NULL);
	rcu_read_unlock();

	return notifier_to_errno(ret);
}

int cpmpm_notify_robust(unsigned long event_up, unsigned long event_down)
{
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&cpu_pm_notifier.lock, flags);
	ret = raw_notifier_call_chain_robust(&cpu_pm_notifier.chain, event_up,
					   event_down, NULL);
	raw_spin_unlock_irqrestore(&cpu_pm_notifier.lock, flags);

	return notifier_to_errno(ret);
}

unsigned long cpmpm_cpu_pm_enter(void) { return CPU_PM_ENTER; }
unsigned long cpmpm_cpu_pm_enter_failed(void) { return CPU_PM_ENTER_FAILED; }
unsigned long cpmpm_cpu_pm_exit(void) { return CPU_PM_EXIT; }
unsigned long cpmpm_cpu_cluster_pm_enter(void) { return CPU_CLUSTER_PM_ENTER; }
unsigned long cpmpm_cpu_cluster_pm_enter_failed(void)
{
	return CPU_CLUSTER_PM_ENTER_FAILED;
}
unsigned long cpmpm_cpu_cluster_pm_exit(void) { return CPU_CLUSTER_PM_EXIT; }

/* Rust-implemented functions */
int cpu_pm_register_notifier(struct notifier_block *nb);
EXPORT_SYMBOL_GPL(cpu_pm_register_notifier);
int cpu_pm_unregister_notifier(struct notifier_block *nb);
EXPORT_SYMBOL_GPL(cpu_pm_unregister_notifier);
int cpu_pm_enter(void);
EXPORT_SYMBOL_GPL(cpu_pm_enter);
int cpu_pm_exit(void);
EXPORT_SYMBOL_GPL(cpu_pm_exit);
int cpu_cluster_pm_enter(void);
EXPORT_SYMBOL_GPL(cpu_cluster_pm_enter);
int cpu_cluster_pm_exit(void);
EXPORT_SYMBOL_GPL(cpu_cluster_pm_exit);

#ifdef CONFIG_PM
static int cpu_pm_suspend(void *data)
{
	int ret;

	ret = cpu_pm_enter();
	if (ret)
		return ret;

	ret = cpu_cluster_pm_enter();
	return ret;
}

static void cpu_pm_resume(void *data)
{
	cpu_cluster_pm_exit();
	cpu_pm_exit();
}

static const struct syscore_ops cpu_pm_syscore_ops = {
	.suspend = cpu_pm_suspend,
	.resume = cpu_pm_resume,
};

static struct syscore cpu_pm_syscore = {
	.ops = &cpu_pm_syscore_ops,
};

static int cpu_pm_init(void)
{
	register_syscore(&cpu_pm_syscore);
	return 0;
}
core_initcall(cpu_pm_init);
#endif
