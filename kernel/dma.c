// SPDX-License-Identifier: GPL-2.0
/*
 * linux/kernel/dma.c: A DMA channel allocator. Inspired by linux/kernel/irq.c.
 *
 * Written by Hennus Bergman, 1992.
 *
 * 1994/12/26: Changes by Alex Nash to fix a minor bug in /proc/dma.
 *   In the previous version the reported device could end up being wrong,
 *   if a device requested a DMA channel that was already in use.
 *   [It also happened to remove the sizeof(char *) == sizeof(int)
 *   assumption introduced because of those /proc/dma patches. -- Hennus]
 */
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <asm/dma.h>



/* A note on resource allocation:
 *
 * All drivers needing DMA channels, should allocate and release them
 * through the public routines `request_dma()' and `free_dma()'.
 *
 * In order to avoid problems, all processes should allocate resources in
 * the same sequence and release them in the reverse order.
 *
 * So, when allocating DMAs and IRQs, first allocate the IRQ, then the DMA.
 * When releasing them, first release the DMA, then release the IRQ.
 * If you don't, you may cause allocation requests to fail unnecessarily.
 * This doesn't really matter now, but it will once we get real semaphores
 * in the kernel.
 */


DEFINE_SPINLOCK(dma_spin_lock);

/*
 * If our port doesn't define this it has no PC like DMA
 */

#ifdef MAX_DMA_CHANNELS


/* Channel n is busy iff dma_chan_busy[n].lock != 0.
 * DMA0 used to be reserved for DRAM refresh, but apparently not any more...
 * DMA4 is reserved for cascading.
 */

struct dma_chan {
	int  lock;
	const char *device_id;
};

static struct dma_chan dma_chan_busy[MAX_DMA_CHANNELS] = {
	[4] = { 1, "cascade" },
};

/* C wrappers for inline/macro primitives callable from Rust */
unsigned int dma_max_channels(void) { return MAX_DMA_CHANNELS; }
int dma_xchg_lock(unsigned int dmanr, int new_val)
{
	return xchg(&dma_chan_busy[dmanr].lock, new_val);
}
void dma_set_device_id(unsigned int dmanr, const char *device_id)
{
	dma_chan_busy[dmanr].device_id = device_id;
}
void dma_print_warn_free(unsigned int dmanr)
{
	printk(KERN_WARNING "Trying to free DMA%d\n", dmanr);
}
void dma_print_warn_free_free(unsigned int dmanr)
{
	printk(KERN_WARNING "Trying to free free DMA%d\n", dmanr);
}

#else /* !MAX_DMA_CHANNELS */

unsigned int dma_max_channels(void) { return 0; }

#endif /* MAX_DMA_CHANNELS */

/* request_dma and free_dma are implemented in dma_rs.rs */
int request_dma(unsigned int dmanr, const char *device_id);
EXPORT_SYMBOL(request_dma);
void free_dma(unsigned int dmanr);
EXPORT_SYMBOL(free_dma);

#ifdef CONFIG_PROC_FS

#ifdef MAX_DMA_CHANNELS
static int proc_dma_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0 ; i < MAX_DMA_CHANNELS ; i++) {
		if (dma_chan_busy[i].lock) {
			seq_printf(m, "%2d: %s\n", i,
				   dma_chan_busy[i].device_id);
		}
	}
	return 0;
}
#else
static int proc_dma_show(struct seq_file *m, void *v)
{
	seq_puts(m, "No DMA\n");
	return 0;
}
#endif /* MAX_DMA_CHANNELS */

static int __init proc_dma_init(void)
{
	proc_create_single("dma", 0, NULL, proc_dma_show);
	return 0;
}

__initcall(proc_dma_init);
#endif

EXPORT_SYMBOL(dma_spin_lock);
