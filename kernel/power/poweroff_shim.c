// SPDX-License-Identifier: GPL-2.0-only
/*
 * poweroff.c - sysrq handler to gracefully power down the machine.
 */
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pm.h>
#include <linux/reboot.h>
#include <linux/sysrq.h>
#include <linux/workqueue.h>

void poweroff_work_rs(struct work_struct *dummy);
void poweroff_handle_sysrq_rs(u8 key);
void poweroff_kernel_power_off(void);
void poweroff_schedule_on_boot_cpu(void);

static DECLARE_WORK(poweroff_work, poweroff_work_rs);

void poweroff_kernel_power_off(void)
{
	kernel_power_off();
}

void poweroff_schedule_on_boot_cpu(void)
{
	schedule_work_on(cpumask_first(cpu_online_mask), &poweroff_work);
}

static const struct sysrq_key_op sysrq_poweroff_op = {
	.handler	= poweroff_handle_sysrq_rs,
	.help_msg	= "poweroff(o)",
	.action_msg	= "Power Off",
	.enable_mask	= SYSRQ_ENABLE_BOOT,
};

static int __init pm_sysrq_init(void)
{
	register_sysrq_key('o', &sysrq_poweroff_op);
	return 0;
}
subsys_initcall(pm_sysrq_init);
