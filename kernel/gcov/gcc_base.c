// SPDX-License-Identifier: GPL-2.0

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include "gcov.h"

static unsigned int gcov_version;

void gcov_base_lock(void)
{
	mutex_lock(&gcov_lock);
}

void gcov_base_unlock(void)
{
	mutex_unlock(&gcov_lock);
}

unsigned int gcov_base_version(void)
{
	return gcov_version;
}

void gcov_base_set_version(unsigned int version)
{
	gcov_version = version;
}

unsigned int gcov_base_info_version(struct gcov_info *info)
{
	return gcov_info_version(info);
}

void gcov_base_print_version(unsigned int version)
{
	pr_info("version magic: 0x%x\n", version);
}

void gcov_base_info_link(struct gcov_info *info)
{
	gcov_info_link(info);
}

bool gcov_base_events_enabled(void)
{
	return gcov_events_enabled;
}

void gcov_base_event_add(struct gcov_info *info)
{
	gcov_event(GCOV_ADD, info);
}

void __gcov_init_rs(struct gcov_info *info);

/*
 * __gcov_init is called by gcc-generated constructor code for each object
 * file compiled with -fprofile-arcs.
 */
void __gcov_init(struct gcov_info *info)
{
	__gcov_init_rs(info);
}
EXPORT_SYMBOL(__gcov_init);

/*
 * These functions may be referenced by gcc-generated profiling code but serve
 * no function for kernel profiling.
 */
void __gcov_flush(void)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_flush);

void __gcov_merge_add(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_add);

void __gcov_merge_single(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_single);

void __gcov_merge_delta(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_delta);

void __gcov_merge_ior(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_ior);

void __gcov_merge_time_profile(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_time_profile);

void __gcov_merge_icall_topn(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_icall_topn);

void __gcov_exit(void)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_exit);
