// SPDX-License-Identifier: GPL-2.0

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/irqnr.h>

#include "internals.h"

/* C wrappers for inline/macro primitives callable from Rust */
unsigned int kexec_nr_irqs(void)
{
	return irq_get_nr_irqs();
}

struct irq_desc *kexec_irq_desc(unsigned int irq)
{
	return irq_to_desc(irq);
}

struct irq_chip *kexec_desc_chip(struct irq_desc *desc)
{
	return irq_desc_get_chip(desc);
}

bool kexec_desc_started(struct irq_desc *desc)
{
	return irqd_is_started(&desc->irq_data);
}

bool kexec_clear_vm_forward_enabled(void)
{
	return IS_ENABLED(CONFIG_GENERIC_IRQ_KEXEC_CLEAR_VM_FORWARD);
}

int kexec_clear_irq_active(unsigned int irq)
{
	return irq_set_irqchip_state(irq, IRQCHIP_STATE_ACTIVE, false);
}

void kexec_maybe_eoi(struct irq_desc *desc, struct irq_chip *chip)
{
	if (chip->irq_eoi && irqd_irq_inprogress(&desc->irq_data))
		chip->irq_eoi(&desc->irq_data);
}

void kexec_irq_shutdown(struct irq_desc *desc)
{
	irq_shutdown(desc);
}

/* Rust-implemented function */
void machine_kexec_mask_interrupts(void);
