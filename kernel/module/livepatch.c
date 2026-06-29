// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Module livepatch support
 *
 * Copyright (C) 2016 Jessica Yu <jeyu@redhat.com>
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "internal.h"

bool module_klp_info_alloc(struct module *mod)
{
	mod->klp_info = kmalloc(sizeof(*mod->klp_info), GFP_KERNEL);
	return mod->klp_info != NULL;
}

void module_klp_copy_hdr(struct module *mod, struct load_info *info)
{
	memcpy(&mod->klp_info->hdr, info->hdr, sizeof(mod->klp_info->hdr));
}

bool module_klp_copy_sechdrs(struct module *mod, struct load_info *info)
{
	unsigned int size = sizeof(*info->sechdrs) * info->hdr->e_shnum;

	mod->klp_info->sechdrs = kmemdup(info->sechdrs, size, GFP_KERNEL);
	return mod->klp_info->sechdrs != NULL;
}

bool module_klp_copy_secstrings(struct module *mod, struct load_info *info)
{
	unsigned int size = info->sechdrs[info->hdr->e_shstrndx].sh_size;

	mod->klp_info->secstrings = kmemdup(info->secstrings, size, GFP_KERNEL);
	return mod->klp_info->secstrings != NULL;
}

unsigned int module_klp_sym_index(struct load_info *info)
{
	return info->index.sym;
}

void module_klp_set_sym_index(struct module *mod, unsigned int symndx)
{
	mod->klp_info->symndx = symndx;
}

void module_klp_repoint_symtab(struct module *mod, unsigned int symndx)
{
	mod->klp_info->sechdrs[symndx].sh_addr =
		(unsigned long)mod->core_kallsyms.symtab;
}

void module_klp_free_sechdrs(struct module *mod)
{
	kfree(mod->klp_info->sechdrs);
}

void module_klp_free_info(struct module *mod)
{
	kfree(mod->klp_info);
}

int copy_module_elf_rs(struct module *mod, struct load_info *info);

/*
 * Persist ELF information about a module. Copy the ELF header,
 * section header table, section string table, and symtab section
 * index from info to mod->klp_info.
 */
int copy_module_elf(struct module *mod, struct load_info *info)
{
	return copy_module_elf_rs(mod, info);
}

void free_module_elf(struct module *mod)
{
	kfree(mod->klp_info->sechdrs);
	kfree(mod->klp_info->secstrings);
	kfree(mod->klp_info);
}
