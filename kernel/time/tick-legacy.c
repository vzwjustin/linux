// SPDX-License-Identifier: GPL-2.0
/*
 * Timer tick function for architectures that lack generic clockevents,
 * consolidated here from m68k/ia64/parisc/arm.
 */

#include <linux/irq.h>
#include <linux/profile.h>
#include <linux/timekeeper_internal.h>

#include "tick-internal.h"

/* C wrappers for inline/macro primitives callable from Rust */
void tl_jiffies_lock(void)
{
	raw_spin_lock(&jiffies_lock);
}

void tl_jiffies_unlock(void)
{
	raw_spin_unlock(&jiffies_lock);
}

void tl_jiffies_seq_begin(void)
{
	write_seqcount_begin(&jiffies_seq);
}

void tl_jiffies_seq_end(void)
{
	write_seqcount_end(&jiffies_seq);
}

void tl_do_timer(unsigned long ticks)
{
	do_timer(ticks);
}

void tl_update_wall_time(void)
{
	update_wall_time();
}

void tl_update_process_times(void)
{
	update_process_times(user_mode(get_irq_regs()));
}

void tl_profile_tick(void)
{
	profile_tick(CPU_PROFILING);
}

/* Rust-implemented function */
void legacy_timer_tick(unsigned long ticks);
