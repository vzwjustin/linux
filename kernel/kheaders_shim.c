// SPDX-License-Identifier: GPL-2.0
/*
 * Provide kernel headers useful to build tracing programs
 * such as for running eBPF tracing tools.
 *
 * (Borrowed code from kernel/configs.c)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/init.h>

/*
 * Define kernel_headers_data and kernel_headers_data_end, within which the
 * compressed kernel headers are stored. The file is first compressed with xz.
 */

asm (
"	.pushsection .rodata, \"a\"		\n"
"	.global kernel_headers_data		\n"
"kernel_headers_data:				\n"
"	.incbin \"kernel/kheaders_data.tar.xz\"	\n"
"	.global kernel_headers_data_end		\n"
"kernel_headers_data_end:			\n"
"	.popsection				\n"
);

extern char kernel_headers_data[];
extern char kernel_headers_data_end[];

static struct bin_attribute kheaders_attr __ro_after_init =
	__BIN_ATTR_SIMPLE_RO(kheaders.tar.xz, 0444);

const void *ikheaders_data_start(void)
{
	return kernel_headers_data;
}

size_t ikheaders_data_size(void)
{
	return kernel_headers_data_end - kernel_headers_data;
}

void ikheaders_attr_set_private(const void *data)
{
	kheaders_attr.private = (void *)data;
}

void ikheaders_attr_set_size(size_t size)
{
	kheaders_attr.size = size;
}

int ikheaders_sysfs_create(void)
{
	return sysfs_create_bin_file(kernel_kobj, &kheaders_attr);
}

void ikheaders_sysfs_remove(void)
{
	sysfs_remove_bin_file(kernel_kobj, &kheaders_attr);
}

int ikheaders_init_rs(void);
void ikheaders_cleanup_rs(void);

static int __init ikheaders_init(void)
{
	return ikheaders_init_rs();
}

static void __exit ikheaders_cleanup(void)
{
	ikheaders_cleanup_rs();
}

module_init(ikheaders_init);
module_exit(ikheaders_cleanup);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Joel Fernandes");
MODULE_DESCRIPTION("Echo the kernel header artifacts used to build the kernel");
