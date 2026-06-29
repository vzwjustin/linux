// SPDX-License-Identifier: GPL-2.0

#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/nmi.h>
#include <linux/percpu-defs.h>

static cpumask_t __read_mostly watchdog_cpus;

/* C wrappers for inline/macro primitives callable from Rust */
unsigned int wb_cpumask_next_wrap(unsigned int cpu)
{
	return cpumask_next_wrap(cpu, &watchdog_cpus);
}

unsigned int wb_nr_cpu_ids(void)
{
	return nr_cpu_ids;
}

void wb_cpumask_set_cpu(unsigned int cpu)
{
	cpumask_set_cpu(cpu, &watchdog_cpus);
}

void wb_cpumask_clear_cpu(unsigned int cpu)
{
	cpumask_clear_cpu(cpu, &watchdog_cpus);
}

void wb_smp_wmb(void)
{
	smp_wmb();
}

void wb_smp_rmb(void)
{
	smp_rmb();
}

unsigned int wb_smp_processor_id(void)
{
	return smp_processor_id();
}

void wb_watchdog_hardlockup_touch_cpu(unsigned int cpu)
{
	watchdog_hardlockup_touch_cpu(cpu);
}

void wb_watchdog_hardlockup_check(unsigned int cpu)
{
	watchdog_hardlockup_check(cpu, NULL);
}

void wb_set_miss_thresh(int val)
{
	watchdog_hardlockup_miss_thresh = val;
}

/* Rust-implemented functions */
int watchdog_hardlockup_probe(void);
void watchdog_hardlockup_enable(unsigned int cpu);
void watchdog_hardlockup_disable(unsigned int cpu);
void watchdog_buddy_check_hardlockup(int hrtimer_interrupts);
