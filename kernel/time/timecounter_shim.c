// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/export.h>
#include <linux/timecounter.h>

void timecounter_init(struct timecounter *tc, struct cyclecounter *cc,
		      u64 start_tstamp);
EXPORT_SYMBOL_GPL(timecounter_init);

u64 timecounter_read(struct timecounter *tc);
EXPORT_SYMBOL_GPL(timecounter_read);
