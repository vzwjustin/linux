# SPDX-License-Identifier: GPL-2.0
obj-y := core.o
ifneq ($(CONFIG_BPF_JIT_ALWAYS_ON),y)
# ___bpf_prog_run() needs GCSE disabled on x86; see 3193c0836f203 for details
cflags-nogcse-$(CONFIG_X86)$(CONFIG_CC_IS_GCC) := -fno-gcse
endif
CFLAGS_core.o += -Wno-override-init $(cflags-nogcse-yy)

obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o helpers.o tnum.o cnum.o log.o token.o liveness.o const_fold.o
obj-$(CONFIG_BPF_SYSCALL) += bpf_iter.o map_iter.o task_iter.o prog_iter.o link_iter.o

# BPF map data structures: C or Rust implementation (mutually exclusive).
# When CONFIG_BPF_RUST_MAPS is selected, the C map source files are excluded
# and Rust implementations from the rust/ subdirectory are linked instead.
bpf-map-objs := hashtab.o arraymap.o lpm_trie.o bloom_filter.o queue_stack_maps.o ringbuf.o

ifeq ($(CONFIG_BPF_RUST_MAPS),y)
obj-$(CONFIG_BPF_SYSCALL) += rust/
obj-$(CONFIG_BPF_SYSCALL) += rust_helpers.o
else
obj-$(CONFIG_BPF_SYSCALL) += $(bpf-map-objs)
endif

obj-$(CONFIG_BPF_SYSCALL) += percpu_freelist.o bpf_lru_list.o map_in_map.o
obj-$(CONFIG_BPF_SYSCALL) += local_storage.o bpf_insn_array.o
obj-$(CONFIG_BPF_SYSCALL) += bpf_local_storage.o bpf_task_storage.o
obj-$(CONFIG_BPF_SYSCALL) += fixups.o cfg.o states.o backtrack.o check_btf.o
obj-${CONFIG_BPF_LSM}	  += bpf_inode_storage.o
obj-$(CONFIG_BPF_SYSCALL) += disasm.o mprog.o
obj-$(CONFIG_BPF_JIT) += trampoline.o
obj-$(CONFIG_BPF_SYSCALL) += btf.o memalloc.o rqspinlock.o stream.o
ifeq ($(CONFIG_MMU)$(CONFIG_64BIT),yy)
obj-$(CONFIG_BPF_SYSCALL) += arena.o range_tree.o
endif
obj-$(CONFIG_BPF_JIT) += dispatcher.o
ifeq ($(CONFIG_NET),y)
obj-$(CONFIG_BPF_SYSCALL) += devmap.o
obj-$(CONFIG_BPF_SYSCALL) += cpumap.o
obj-$(CONFIG_BPF_SYSCALL) += offload.o
obj-$(CONFIG_BPF_SYSCALL) += net_namespace.o
obj-$(CONFIG_BPF_SYSCALL) += tcx.o
endif
ifeq ($(CONFIG_PERF_EVENTS),y)
obj-$(CONFIG_BPF_SYSCALL) += stackmap.o
endif
ifeq ($(CONFIG_CGROUPS),y)
obj-$(CONFIG_BPF_SYSCALL) += cgroup_iter.o bpf_cgrp_storage.o
endif
obj-$(CONFIG_CGROUP_BPF) += cgroup.o
ifeq ($(CONFIG_INET),y)
obj-$(CONFIG_BPF_SYSCALL) += reuseport_array.o
endif
ifeq ($(CONFIG_SYSFS),y)
obj-$(CONFIG_DEBUG_INFO_BTF) += sysfs_btf.o
endif
ifeq ($(CONFIG_BPF_JIT),y)
obj-$(CONFIG_BPF_SYSCALL) += bpf_struct_ops.o
obj-$(CONFIG_BPF_SYSCALL) += cpumask.o
# bpf_lsm_proto.o must precede bpf_lsm.o. The current pahole logic
# deduplicates function prototypes within
# btf_encoder__add_saved_func() by keeping the first instance seen. We
# need the function prototype(s) in bpf_lsm_proto.o to take precedence
# over those within bpf_lsm.o. Having bpf_lsm_proto.o precede
# bpf_lsm.o ensures its DWARF CU is processed early, forcing the
# generated BTF to contain the overrides.
#
# Notably, this is a temporary workaround whilst the deduplication
# semantics within pahole are revisited accordingly.
obj-${CONFIG_BPF_LSM} += bpf_lsm_proto.o bpf_lsm.o
endif
ifneq ($(CONFIG_CRYPTO),)
obj-$(CONFIG_BPF_SYSCALL) += crypto.o
endif
obj-$(CONFIG_BPF_PRELOAD) += preload/

obj-$(CONFIG_BPF_SYSCALL) += relo_core.o
obj-$(CONFIG_BPF_SYSCALL) += btf_iter.o
obj-$(CONFIG_BPF_SYSCALL) += btf_relocate.o
obj-$(CONFIG_BPF_SYSCALL) += kmem_cache_iter.o
ifeq ($(CONFIG_DMA_SHARED_BUFFER),y)
obj-$(CONFIG_BPF_SYSCALL) += dmabuf_iter.o
endif

CFLAGS_REMOVE_percpu_freelist.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_bpf_lru_list.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_queue_stack_maps.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_lpm_trie.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_ringbuf.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_rqspinlock.o = $(CC_FLAGS_FTRACE)

# ---------------------------------------------------------------------------
# Rust BPF map bindgen support
# ---------------------------------------------------------------------------
# When CONFIG_BPF_RUST_MAPS is enabled, generate Rust FFI bindings from the
# relevant C headers using bindgen. Dependency tracking ensures that changes
# to any referenced C header trigger regeneration of bindings.rs.

ifeq ($(CONFIG_BPF_RUST_MAPS),y)

BPF_RUST_DIR := $(src)/rust
BPF_BINDINGS := $(BPF_RUST_DIR)/bindings.rs

# C headers that feed into bindgen. Modifications to any of these trigger
# regeneration of bindings.rs and recompilation of dependent Rust modules.
BPF_BINDGEN_HEADERS := \
	$(srctree)/include/linux/bpf.h \
	$(srctree)/include/linux/bpf_types.h \
	$(srctree)/include/uapi/linux/bpf.h \
	$(src)/map_in_map.h \
	$(src)/bpf_lru_list.h \
	$(src)/percpu_freelist.h \
	$(src)/rqspinlock.h

# Bindgen flags for kernel Rust bindings generation.
BPF_BINDGEN_FLAGS := \
	--use-core \
	--no-layout-tests \
	--no-doc-comments \
	--with-derive-default \
	-- \
	-I$(srctree)/include \
	-I$(srctree)/include/uapi \
	-I$(srctree)/arch/$(SRCARCH)/include \
	-I$(srctree)/arch/$(SRCARCH)/include/generated \
	-I$(objtree)/include \
	-I$(objtree)/include/generated \
	-D__KERNEL__ \
	-DMODULE

# Rule: generate bindings.rs from C headers via bindgen.
# The generated file is placed in the Rust source directory so that rustc
# can include it directly. A .d dependency file is emitted alongside so
# that make tracks header modifications for incremental rebuilds.
$(BPF_BINDINGS): $(BPF_BINDGEN_HEADERS) FORCE
	$(call if_changed,bpf_bindgen)

quiet_cmd_bpf_bindgen = BINDGEN $@
      cmd_bpf_bindgen = $(BINDGEN) $(srctree)/include/linux/bpf.h \
	--allowlist-type 'bpf_map|bpf_attr|bpf_map_type|rqspinlock_t|bpf_mem_alloc' \
	--allowlist-function 'bpf_map_area_alloc|bpf_map_area_free|bpf_map_init_from_attr|__kmalloc|kfree|_copy_from_user' \
	--allowlist-var 'BPF_.*|GFP_KERNEL|GFP_ATOMIC' \
	$(BPF_BINDGEN_FLAGS) \
	-o $@

# Ensure bindings are generated before Rust compilation begins.
# The rust/ subdirectory Makefile depends on this target.
$(BPF_RUST_DIR)/lib.rs: $(BPF_BINDINGS)

endif # CONFIG_BPF_RUST_MAPS
