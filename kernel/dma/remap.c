// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2014 The Linux Foundation
 */
#include <linux/dma-map-ops.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

/* C wrappers for vmalloc helpers callable from Rust */
unsigned long remap_vm_area_flags(void *cpu_addr)
{
	struct vm_struct *area = find_vm_area(cpu_addr);

	if (!area)
		return 0;
	return area->flags;
}

struct page **remap_vm_area_pages(void *cpu_addr)
{
	return find_vm_area(cpu_addr)->pages;
}

void remap_warn_unexpected_vm_flags(void *cpu_addr)
{
	WARN(find_vm_area(cpu_addr)->flags != VM_DMA_COHERENT,
	     "unexpected flags in area: %p\n", cpu_addr);
}

void remap_warn_invalid_free(void *cpu_addr)
{
	WARN(1, "trying to free invalid coherent area: %p\n", cpu_addr);
}

unsigned long remap_vm_dma_coherent_flag(void)
{
	return VM_DMA_COHERENT;
}

void remap_vunmap(void *cpu_addr)
{
	vunmap(cpu_addr);
}

/* Rust-implemented functions */
struct page **dma_common_find_pages(void *cpu_addr);
void dma_common_free_remap(void *cpu_addr, size_t size);

/*
 * Remaps an array of PAGE_SIZE pages into another vm_area.
 * Cannot be used in non-sleeping contexts
 */
void *dma_common_pages_remap(struct page **pages, size_t size,
			 pgprot_t prot, const void *caller)
{
	void *vaddr;

	vaddr = vmap(pages, PAGE_ALIGN(size) >> PAGE_SHIFT,
		     VM_DMA_COHERENT, prot);
	if (vaddr)
		find_vm_area(vaddr)->pages = pages;
	return vaddr;
}

/*
 * Remaps an allocated contiguous region into another vm_area.
 * Cannot be used in non-sleeping contexts
 */
void *dma_common_contiguous_remap(struct page *page, size_t size,
			pgprot_t prot, const void *caller)
{
	int count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	struct page **pages;
	void *vaddr;
	int i;

	pages = kvmalloc_objs(struct page *, count);
	if (!pages)
		return NULL;
	for (i = 0; i < count; i++)
		pages[i] = page++;
	vaddr = vmap(pages, count, VM_DMA_COHERENT, prot);
	kvfree(pages);

	return vaddr;
}
