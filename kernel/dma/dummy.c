// SPDX-License-Identifier: GPL-2.0
/*
 * Dummy DMA ops that always fail.
 */
#include <linux/dma-map-ops.h>

void dma_dummy_warn_once(void)
{
	WARN_ON_ONCE(true);
}

dma_addr_t dma_dummy_mapping_error(void)
{
	return DMA_MAPPING_ERROR;
}

int dma_dummy_mmap_rs(struct device *dev, struct vm_area_struct *vma,
		void *cpu_addr, dma_addr_t dma_addr, size_t size,
		unsigned long attrs);
dma_addr_t dma_dummy_map_phys_rs(struct device *dev, phys_addr_t phys,
		size_t size, enum dma_data_direction dir, unsigned long attrs);
void dma_dummy_unmap_phys_rs(struct device *dev, dma_addr_t dma_handle,
		size_t size, enum dma_data_direction dir, unsigned long attrs);
int dma_dummy_map_sg_rs(struct device *dev, struct scatterlist *sgl,
		int nelems, enum dma_data_direction dir,
		unsigned long attrs);
void dma_dummy_unmap_sg_rs(struct device *dev, struct scatterlist *sgl,
		int nelems, enum dma_data_direction dir,
		unsigned long attrs);
int dma_dummy_supported_rs(struct device *hwdev, u64 mask);

const struct dma_map_ops dma_dummy_ops = {
	.mmap                   = dma_dummy_mmap_rs,
	.map_phys               = dma_dummy_map_phys_rs,
	.unmap_phys             = dma_dummy_unmap_phys_rs,
	.map_sg                 = dma_dummy_map_sg_rs,
	.unmap_sg               = dma_dummy_unmap_sg_rs,
	.dma_supported          = dma_dummy_supported_rs,
};
