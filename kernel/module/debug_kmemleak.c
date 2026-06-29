// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Module kmemleak support
 *
 * Copyright (C) 2009 Catalin Marinas
 */

#include <linux/module.h>
#include <linux/kmemleak.h>
#include "internal.h"

unsigned int module_kmemleak_mem_type_count(void)
{
	return MOD_MEM_NUM_TYPES;
}

unsigned int module_kmemleak_data_type(void)
{
	return MOD_DATA;
}

unsigned int module_kmemleak_init_data_type(void)
{
	return MOD_INIT_DATA;
}

bool module_kmemleak_mem_is_rox(const struct module *mod, unsigned int type)
{
	return mod->mem[type].is_rox;
}

void *module_kmemleak_mem_base(const struct module *mod, unsigned int type)
{
	return mod->mem[type].base;
}

void module_kmemleak_no_scan(void *ptr)
{
	kmemleak_no_scan(ptr);
}

void kmemleak_load_module_rs(const struct module *mod, const struct load_info *info);

void kmemleak_load_module(const struct module *mod,
			  const struct load_info *info)
{
	kmemleak_load_module_rs(mod, info);
}
