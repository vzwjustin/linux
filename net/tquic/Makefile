# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the TQUIC WAN Bonding subsystem
#

obj-$(CONFIG_TQUIC) += tquic.o

tquic-y := \
	tquic_main.o \
	tquic_protocol.o \
	tquic_connection.o \
	tquic_stream.o \
	tquic_packet.o \
	tquic_frame.o \
	tquic_socket.o \
	tquic_output.o \
	tquic_input.o \
	tquic_timer.o \
	tquic_recovery.o

# Core protocol components
obj-$(CONFIG_TQUIC_CORE) += tquic_core.o
tquic_core-y := \
	core/protocol.o \
	core/connection.o \
	core/stream.o \
	core/frame.o \
	core/packet.o \
	core/ack.o \
	core/flow_control.o

# WAN Bonding components
obj-$(CONFIG_TQUIC_WAN_BONDING) += tquic_bond.o
tquic_bond-y := \
	bond/bonding.o \
	bond/interface.o \
	bond/path.o \
	bond/failover.o \
	bond/aggregation.o \
	bond/migration.o

# Path Manager
obj-$(CONFIG_TQUIC_PATH_MANAGER) += tquic_pm.o
tquic_pm-y := \
	pm/path_manager.o \
	pm/path_probe.o \
	pm/path_quality.o \
	pm/path_selection.o

# Packet Scheduler
obj-$(CONFIG_TQUIC_SCHEDULER) += tquic_sched.o
tquic_sched-y := \
	sched/scheduler.o \
	sched/sched_rr.o \
	sched/sched_wrr.o \
	sched/sched_minrtt.o \
	sched/sched_redundant.o \
	sched/sched_blest.o \
	sched/reorder.o

# Congestion Control
obj-$(CONFIG_TQUIC_CONG_CUBIC) += tquic_cubic.o
obj-$(CONFIG_TQUIC_CONG_BBR) += tquic_bbr.o
obj-$(CONFIG_TQUIC_CONG_COPA) += tquic_copa.o
obj-$(CONFIG_TQUIC_CONG_WESTWOOD) += tquic_westwood.o

tquic_cubic-y := cong/cubic.o
tquic_bbr-y := cong/bbr.o
tquic_copa-y := cong/copa.o
tquic_westwood-y := cong/westwood.o

# Crypto support
obj-$(CONFIG_TQUIC_CRYPTO) += tquic_crypto.o
tquic_crypto-y := \
	crypto/tls.o \
	crypto/keys.o \
	crypto/cipher.o \
	crypto/handshake.o

# Diagnostics
obj-$(CONFIG_TQUIC_DIAG) += tquic_diag.o

# Debugging
tquic-$(CONFIG_TQUIC_DEBUGFS) += debugfs.o

# KUnit tests
obj-$(CONFIG_TQUIC_KUNIT_TEST) += tquic_test.o
tquic_test-y := \
	test/protocol_test.o \
	test/connection_test.o \
	test/path_test.o \
	test/scheduler_test.o
