// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Module strict rwx
 *
 * Copyright (C) 2015 Rusty Russell
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include <linux/execmem.h>
#include "internal.h"

bool module_strict_rwx_enabled_rs_helper(void)
{
	return IS_ENABLED(CONFIG_STRICT_MODULE_RWX);
}

bool module_have_static_call_inline_rs_helper(void)
{
	return IS_ENABLED(CONFIG_HAVE_STATIC_CALL_INLINE);
}

unsigned int module_elf_shnum_rs_helper(const Elf_Ehdr *hdr)
{
	return hdr->e_shnum;
}

bool module_section_has_wx_rs_helper(const Elf_Shdr *sechdrs, unsigned int i)
{
	const unsigned long shf_wx = SHF_WRITE | SHF_EXECINSTR;

	return (sechdrs[i].sh_flags & shf_wx) == shf_wx;
}

const char *module_section_name_rs_helper(const Elf_Shdr *sechdrs,
					 const char *secstrings, unsigned int i)
{
	return secstrings + sechdrs[i].sh_name;
}

void module_mark_section_ro_after_init_rs_helper(Elf_Shdr *sechdrs,
						unsigned int i)
{
	sechdrs[i].sh_flags |= SHF_RO_AFTER_INIT;
}

void module_enforce_rwx_pr_err_rs_helper(const char *modname,
					const char *secname, unsigned int i)
{
	pr_err("%s: section %s (index %u) has invalid WRITE|EXEC flags\n",
	       modname, secname, i);
}

int module_enforce_rwx_sections_rs(const Elf_Ehdr *hdr,
				   const Elf_Shdr *sechdrs,
				   const char *secstrings, const char *modname,
				   int enoexec);
void module_mark_ro_after_init_rs(const Elf_Ehdr *hdr, Elf_Shdr *sechdrs,
				  const char *secstrings);

static int module_set_memory(const struct module *mod, enum mod_mem_type type,
			     int (*set_memory)(unsigned long start, int num_pages))
{
	const struct module_memory *mod_mem = &mod->mem[type];

	if (!mod_mem->base)
		return 0;

	set_vm_flush_reset_perms(mod_mem->base);
	return set_memory((unsigned long)mod_mem->base, mod_mem->size >> PAGE_SHIFT);
}

/*
 * Since some arches are moving towards PAGE_KERNEL module allocations instead
 * of PAGE_KERNEL_EXEC, keep module_enable_x() independent of
 * CONFIG_STRICT_MODULE_RWX because they are needed regardless of whether we
 * are strict.
 */
int module_enable_text_rox(const struct module *mod)
{
	for_class_mod_mem_type(type, text) {
		const struct module_memory *mem = &mod->mem[type];
		int ret;

		if (mem->is_rox)
			ret = execmem_restore_rox(mem->base, mem->size);
		else if (IS_ENABLED(CONFIG_STRICT_MODULE_RWX))
			ret = module_set_memory(mod, type, set_memory_rox);
		else
			ret = module_set_memory(mod, type, set_memory_x);
		if (ret)
			return ret;
	}
	return 0;
}

int module_enable_rodata_ro(const struct module *mod)
{
	int ret;

	if (!IS_ENABLED(CONFIG_STRICT_MODULE_RWX) || !rodata_enabled)
		return 0;

	ret = module_set_memory(mod, MOD_RODATA, set_memory_ro);
	if (ret)
		return ret;
	ret = module_set_memory(mod, MOD_INIT_RODATA, set_memory_ro);
	if (ret)
		return ret;

	return 0;
}

int module_enable_rodata_ro_after_init(const struct module *mod)
{
	if (!IS_ENABLED(CONFIG_STRICT_MODULE_RWX) || !rodata_enabled)
		return 0;

	return module_set_memory(mod, MOD_RO_AFTER_INIT, set_memory_ro);
}

int module_enable_data_nx(const struct module *mod)
{
	if (!IS_ENABLED(CONFIG_STRICT_MODULE_RWX))
		return 0;

	for_class_mod_mem_type(type, data) {
		int ret = module_set_memory(mod, type, set_memory_nx);

		if (ret)
			return ret;
	}
	return 0;
}

int module_enforce_rwx_sections(const Elf_Ehdr *hdr, const Elf_Shdr *sechdrs,
				const char *secstrings,
				const struct module *mod)
{
	return module_enforce_rwx_sections_rs(hdr, sechdrs, secstrings,
					       mod->name, -ENOEXEC);
}

void module_mark_ro_after_init(const Elf_Ehdr *hdr, Elf_Shdr *sechdrs,
			       const char *secstrings)
{
	module_mark_ro_after_init_rs(hdr, sechdrs, secstrings);
}
