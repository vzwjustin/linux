# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the BPF Rust map implementations.
#
# This Makefile is invoked by kbuild when CONFIG_BPF_RUST_MAPS=y.
# It compiles individual Rust source files into object files using rustc,
# supporting incremental compilation: modifying a single .rs file only
# rebuilds that file and its direct dependents.

# Rust compiler flags for kernel module compilation.
BPF_RUST_EDITION := 2021
BPF_RUSTC_FLAGS := \
	--edition=$(BPF_RUST_EDITION) \
	-Cpanic=abort \
	-Copt-level=2 \
	-Ccodegen-units=1 \
	--cfg 'no_std' \
	-Zcrate-attr='feature(no_core)' \
	--extern alloc

# Object files produced by the Rust BPF map crate.
# Each .rs module compiles to a .o file. Only the crate root (lib.rs)
# is listed here; rustc handles intra-crate dependencies internally.
obj-$(CONFIG_BPF_RUST_MAPS) += bpf_rust_maps.o

# The composite object is built from the Rust crate root.
bpf_rust_maps-y := lib.o

# Rule: compile Rust crate root into an object file.
# Kbuild's built-in Rust support (scripts/Makefile.build) handles .rs -> .o
# when CONFIG_RUST is enabled. The dependency on bindings.rs ensures bindgen
# runs first.
$(obj)/lib.o: $(src)/lib.rs $(src)/bindings.rs

# Ensure all Rust source files trigger rebuild when modified.
# Kbuild tracks individual file timestamps; listing explicit deps for
# sub-modules enables single-file incremental rebuild.
$(src)/lib.rs: \
	$(src)/abstractions/mod.rs \
	$(src)/abstractions/lock.rs \
	$(src)/abstractions/alloc.rs \
	$(src)/abstractions/bpf_mem.rs \
	$(src)/abstractions/rcu.rs \
	$(src)/abstractions/bitmap.rs
