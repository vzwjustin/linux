// SPDX-License-Identifier: GPL-2.0-only
#include <linux/crash_dump.h>
#include <linux/export.h>
#include <linux/init.h>

/*
 * Stores the physical address of the elf header of the crash image.
 *
 * Note: elfcorehdr_addr is not just limited to vmcore. It is also used by
 * is_kdump_kernel() to determine if we are booting after a panic. Hence put
 * it under CONFIG_CRASH_DUMP and not CONFIG_PROC_VMCORE.
 */
unsigned long long elfcorehdr_addr = ELFCORE_ADDR_MAX;
EXPORT_SYMBOL_GPL(elfcorehdr_addr);

/* Stores the size of the elf header of the crash image. */
unsigned long long elfcorehdr_size;

int setup_elfcorehdr_rs(char *arg, unsigned long long *addr,
			unsigned long long *size);

/*
 * elfcorehdr= specifies the location of elf core header stored by the crashed
 * kernel. This option will be passed by kexec loader to the capture kernel.
 *
 * Syntax: elfcorehdr=[size[KMG]@]offset[KMG]
 */
static int __init setup_elfcorehdr(char *arg)
{
	return setup_elfcorehdr_rs(arg, &elfcorehdr_addr, &elfcorehdr_size);
}
early_param("elfcorehdr", setup_elfcorehdr);
