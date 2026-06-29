// SPDX-License-Identifier: GPL-2.0-only
/*
 * kexec_handover_debug.c - kexec handover optional debug functionality
 * Copyright (C) 2025 Google LLC, Pasha Tatashin <pasha.tatashin@soleen.com>
 */

#define pr_fmt(fmt) "KHO: " fmt

#include "kexec_handover_internal.h"

unsigned int kho_scratch_count(void)
{
	return kho_scratch_cnt;
}

phys_addr_t kho_scratch_addr(unsigned int i)
{
	return kho_scratch[i].addr;
}

size_t kho_scratch_size(unsigned int i)
{
	return kho_scratch[i].size;
}

bool kho_scratch_overlap_rs(phys_addr_t phys, size_t size);

bool kho_scratch_overlap(phys_addr_t phys, size_t size)
{
	return kho_scratch_overlap_rs(phys, size);
}
