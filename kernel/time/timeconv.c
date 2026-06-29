// SPDX-License-Identifier: LGPL-2.0+
/*
 * Copyright (C) 1993, 1994, 1995, 1996, 1997 Free Software Foundation, Inc.
 * This file is part of the GNU C Library.
 * Contributed by Paul Eggert (eggert@twinsun.com).
 *
 * The GNU C Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * The GNU C Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with the GNU C Library; see the file COPYING.LIB.  If not,
 * write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * Converts the calendar time to broken-down time representation
 *
 * 2009-7-14:
 *   Moved from glibc-2.6 to kernel by Zhaolei<zhaolei@cn.fujitsu.com>
 * 2021-06-02:
 *   Reimplemented by Cassio Neri <cassio.neri@gmail.com>
 */

#include <linux/time.h>
#include <linux/module.h>

void time64_to_tm_rs(time64_t totalsecs, int offset, struct tm *result);

/**
 * time64_to_tm - converts the calendar time to local broken-down time
 *
 * @totalsecs:	the number of seconds elapsed since 00:00:00 on January 1, 1970,
 *		Coordinated Universal Time (UTC).
 * @offset:	offset seconds adding to totalsecs.
 * @result:	pointer to struct tm variable to receive broken-down time
 */
void time64_to_tm(time64_t totalsecs, int offset, struct tm *result)
{
	time64_to_tm_rs(totalsecs, offset, result);
}
EXPORT_SYMBOL(time64_to_tm);
