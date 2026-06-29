// SPDX-License-Identifier: GPL-2.0
/*
 * Handling of different ABIs (personalities).
 *
 * We group personalities into execution domains which have their
 * own handlers for kernel entry points, signal mapping, etc...
 *
 * 2001-05-06	Complete rewrite,  Christoph Hellwig (hch@infradead.org)
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/personality.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/sysctl.h>
#include <linux/types.h>

#ifdef CONFIG_PROC_FS
int execdomains_proc_show_rs(struct seq_file *m);

static int execdomains_proc_show(struct seq_file *m, void *v)
{
	return execdomains_proc_show_rs(m);
}

static int __init proc_execdomains_init(void)
{
	proc_create_single("execdomains", 0, NULL, execdomains_proc_show);
	return 0;
}
module_init(proc_execdomains_init);
#endif

/* C wrappers for inline/macro primitives callable from Rust */
unsigned int ed_get_personality(void) { return current->personality; }
void ed_set_personality(unsigned int pers) { set_personality(pers); }

/* personality syscall logic implemented in exec_domain_rs.rs */
unsigned int ksys_personality_rs(unsigned int personality);

SYSCALL_DEFINE1(personality, unsigned int, personality)
{
	return ksys_personality_rs(personality);
}
