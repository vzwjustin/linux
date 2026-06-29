// SPDX-License-Identifier: GPL-2.0

#include <linux/entry-virt.h>

/* C wrappers for inline/macro primitives callable from Rust */
unsigned long virt_read_thread_flags(void)
{
	return read_thread_flags();
}

unsigned long virt_xfer_to_guest_mode_work_mask(void)
{
	return XFER_TO_GUEST_MODE_WORK;
}

unsigned long virt_mask_sigpending_notify(void)
{
	return _TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL;
}

unsigned long virt_mask_need_resched(void)
{
	return _TIF_NEED_RESCHED | _TIF_NEED_RESCHED_LAZY;
}

unsigned long virt_mask_notify_resume(void)
{
	return _TIF_NOTIFY_RESUME;
}

void virt_schedule(void)
{
	schedule();
}

void virt_resume_user_mode_work(void)
{
	resume_user_mode_work(NULL);
}

int virt_arch_xfer_to_guest_mode_handle_work(unsigned long ti_work)
{
	return arch_xfer_to_guest_mode_handle_work(ti_work);
}

/* Rust-implemented function */
int xfer_to_guest_mode_handle_work(void);
EXPORT_SYMBOL_GPL(xfer_to_guest_mode_handle_work);
