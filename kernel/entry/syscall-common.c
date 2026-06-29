// SPDX-License-Identifier: GPL-2.0

#include <linux/entry-common.h>

#define CREATE_TRACE_POINTS
#include <trace/events/syscalls.h>

/* C wrappers for tracepoints and inlines callable from Rust */
void syscall_common_trace_sys_enter(struct pt_regs *regs, long syscall)
{
	trace_sys_enter(regs, syscall);
}

long syscall_common_syscall_get_nr(struct pt_regs *regs)
{
	return syscall_get_nr(current, regs);
}

void syscall_common_trace_sys_exit(struct pt_regs *regs, long ret)
{
	trace_sys_exit(regs, ret);
}

/* Rust-implemented functions */
long trace_syscall_enter(struct pt_regs *regs, long syscall);
void trace_syscall_exit(struct pt_regs *regs, long ret);
