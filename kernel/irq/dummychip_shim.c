// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006, Thomas Gleixner, Russell King
 *
 * This file contains dummy interrupt chip implementation.
 */
#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/irq.h>

#include "internals.h"

/*
 * What should we do if we get a hw irq event on an illegal vector?
 * Each architecture has to answer this themselves.
 */
static void ack_bad(struct irq_data *data)
{
	struct irq_desc *desc = irq_data_to_desc(data);

	print_irq_desc(data->irq, desc);
	ack_bad_irq(data->irq);
}

void irq_dummy_noop_rs(struct irq_data *data);
unsigned int irq_dummy_noop_ret_rs(struct irq_data *data);

/* Generic no controller implementation */
struct irq_chip no_irq_chip = {
	.name		= "none",
	.irq_startup	= irq_dummy_noop_ret_rs,
	.irq_shutdown	= irq_dummy_noop_rs,
	.irq_enable	= irq_dummy_noop_rs,
	.irq_disable	= irq_dummy_noop_rs,
	.irq_ack	= ack_bad,
	.flags		= IRQCHIP_SKIP_SET_WAKE,
};

/*
 * Generic dummy implementation which can be used for real dumb interrupt
 * sources.
 */
struct irq_chip dummy_irq_chip = {
	.name		= "dummy",
	.irq_startup	= irq_dummy_noop_ret_rs,
	.irq_shutdown	= irq_dummy_noop_rs,
	.irq_enable	= irq_dummy_noop_rs,
	.irq_disable	= irq_dummy_noop_rs,
	.irq_ack	= irq_dummy_noop_rs,
	.irq_mask	= irq_dummy_noop_rs,
	.irq_unmask	= irq_dummy_noop_rs,
	.flags		= IRQCHIP_SKIP_SET_WAKE,
};
EXPORT_SYMBOL_GPL(dummy_irq_chip);
