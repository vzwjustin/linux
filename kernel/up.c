// SPDX-License-Identifier: GPL-2.0-only
/*
 * Uniprocessor-only support functions.  The counterpart to kernel/smp.c
 */

#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/smp.h>
#include <linux/hypervisor.h>

/* Wrappers for inline functions so Rust can call them. */
void up_local_irq_save(unsigned long *flags)
{
	local_irq_save(*flags);
}

void up_local_irq_restore(unsigned long flags)
{
	local_irq_restore(flags);
}

void up_preempt_disable(void)
{
	preempt_disable();
}

void up_preempt_enable(void)
{
	preempt_enable();
}

bool up_cpumask_test_cpu(int cpu, const struct cpumask *mask)
{
	return cpumask_test_cpu(cpu, mask);
}

void up_hypervisor_pin_vcpu(int cpu)
{
	hypervisor_pin_vcpu(cpu);
}

void up_call_csd_func(call_single_data_t *csd)
{
	csd->func(csd->info);
}

/* Rust implementations. */
int smp_call_function_single(int cpu, void (*func)(void *info), void *info,
			     int wait);
EXPORT_SYMBOL(smp_call_function_single);

int smp_call_function_single_async(int cpu, call_single_data_t *csd);
EXPORT_SYMBOL(smp_call_function_single_async);

void on_each_cpu_cond_mask(smp_cond_func_t cond_func, smp_call_func_t func,
			   void *info, bool wait, const struct cpumask *mask);
EXPORT_SYMBOL(on_each_cpu_cond_mask);

int smp_call_on_cpu(unsigned int cpu, int (*func)(void *), void *par,
		    bool phys);
EXPORT_SYMBOL_GPL(smp_call_on_cpu);
