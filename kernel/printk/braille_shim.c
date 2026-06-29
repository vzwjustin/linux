// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/console.h>
#include <linux/errno.h>
#include <linux/kernel.h>

#include "console_cmdline.h"
#include "braille.h"

int _braille_console_setup(char **str, char **brl_options);

int _braille_register_console(struct console *console, struct console_cmdline *c)
{
	int rtn = 0;

	if (c->brl_options) {
		console->flags |= CON_BRL;
		rtn = braille_register_console(console, c->index, c->options,
					       c->brl_options);
	}

	return rtn;
}

int _braille_unregister_console(struct console *console)
{
	if (console->flags & CON_BRL)
		return braille_unregister_console(console);
	return 0;
}
