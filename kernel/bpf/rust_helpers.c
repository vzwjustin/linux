// SPDX-License-Identifier: GPL-2.0
/*
 * rust_helpers.c - C helper functions for Rust BPF modules.
 *
 * Some kernel macros (like BUG()) expand to compiler builtins or inline
 * assembly that cannot be directly invoked from Rust. This file provides
 * thin C wrappers that Rust code can call via extern "C" declarations.
 */

#include <linux/bug.h>

/*
 * kernel_bug - Wrapper around the BUG() macro for Rust's panic handler.
 *
 * The Rust crate is compiled with panic = "abort" and provides a custom
 * #[panic_handler] that calls this function. BUG() triggers a kernel oops
 * with a full register dump and backtrace, which is the expected behavior
 * when kernel code encounters an unrecoverable error.
 *
 * This function is marked __noreturn because BUG() never returns.
 */
void __noreturn kernel_bug(void)
{
	BUG();
}
