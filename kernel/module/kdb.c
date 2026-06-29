// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Module kdb support
 *
 * Copyright (C) 2010 Jason Wessel
 */

#include <linux/module.h>
#include <linux/kdb.h>
#include "internal.h"

bool module_kdb_is_unformed_rs_helper(const struct module *mod)
{
	return mod->state == MODULE_STATE_UNFORMED;
}

bool module_kdb_is_going_rs_helper(const struct module *mod)
{
	return mod->state == MODULE_STATE_GOING;
}

bool module_kdb_is_coming_rs_helper(const struct module *mod)
{
	return mod->state == MODULE_STATE_COMING;
}

unsigned int module_kdb_text_size_rs_helper(const struct module *mod)
{
	return mod->mem[MOD_TEXT].size;
}

unsigned int module_kdb_rodata_size_rs_helper(const struct module *mod)
{
	return mod->mem[MOD_RODATA].size;
}

unsigned int module_kdb_ro_after_init_size_rs_helper(const struct module *mod)
{
	return mod->mem[MOD_RO_AFTER_INIT].size;
}

unsigned int module_kdb_data_size_rs_helper(const struct module *mod)
{
	return mod->mem[MOD_DATA].size;
}

void *module_kdb_text_base_rs_helper(const struct module *mod)
{
	return mod->mem[MOD_TEXT].base;
}

void *module_kdb_rodata_base_rs_helper(const struct module *mod)
{
	return mod->mem[MOD_RODATA].base;
}

void *module_kdb_ro_after_init_base_rs_helper(const struct module *mod)
{
	return mod->mem[MOD_RO_AFTER_INIT].base;
}

void *module_kdb_data_base_rs_helper(const struct module *mod)
{
	return mod->mem[MOD_DATA].base;
}

bool module_kdb_is_unformed_rs(const struct module *mod);
unsigned int module_kdb_text_size_rs(const struct module *mod);
unsigned int module_kdb_rodata_size_rs(const struct module *mod);
unsigned int module_kdb_ro_after_init_size_rs(const struct module *mod);
unsigned int module_kdb_data_size_rs(const struct module *mod);
const char *module_kdb_state_name_rs(const struct module *mod);
void *module_kdb_text_base_rs(const struct module *mod);
void *module_kdb_rodata_base_rs(const struct module *mod);
void *module_kdb_ro_after_init_base_rs(const struct module *mod);
void *module_kdb_data_base_rs(const struct module *mod);

/*
 * kdb_lsmod - This function implements the 'lsmod' command.  Lists
 *	currently loaded kernel modules.
 *	Mostly taken from userland lsmod.
 */
int kdb_lsmod(int argc, const char **argv)
{
	struct module *mod;

	if (argc != 0)
		return KDB_ARGCOUNT;

	kdb_printf("Module                  Size  modstruct     Used by\n");
	list_for_each_entry(mod, &modules, list) {
		if (module_kdb_is_unformed_rs(mod))
			continue;

		kdb_printf("%-20s%8u", mod->name, module_kdb_text_size_rs(mod));
		kdb_printf("/%8u", module_kdb_rodata_size_rs(mod));
		kdb_printf("/%8u", module_kdb_ro_after_init_size_rs(mod));
		kdb_printf("/%8u", module_kdb_data_size_rs(mod));

		kdb_printf("  0x%px ", (void *)mod);
#ifdef CONFIG_MODULE_UNLOAD
		kdb_printf("%4d ", module_refcount(mod));
#endif
		kdb_printf("%s", module_kdb_state_name_rs(mod));
		kdb_printf(" 0x%px", module_kdb_text_base_rs(mod));
		kdb_printf("/0x%px", module_kdb_rodata_base_rs(mod));
		kdb_printf("/0x%px", module_kdb_ro_after_init_base_rs(mod));
		kdb_printf("/0x%px", module_kdb_data_base_rs(mod));

#ifdef CONFIG_MODULE_UNLOAD
		{
			struct module_use *use;

			kdb_printf(" [ ");
			list_for_each_entry(use, &mod->source_list,
					    source_list)
				kdb_printf("%s ", use->target->name);
			kdb_printf("]\n");
		}
#endif
	}

	return 0;
}
