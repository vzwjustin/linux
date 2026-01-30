# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the TQUIC WAN Bonding subsystem
#

obj-$(CONFIG_TQUIC) += tquic.o

# Main TQUIC module
tquic-y := \
	tquic_main.o \
	tquic_proto.o \
	tquic_socket.o \
	tquic_netlink.o \
	tquic_sysctl.o \
	tquic_udp.o \
	tquic_output.o \
	tquic_input.o \
	tquic_timer.o

# Core protocol components
obj-$(CONFIG_TQUIC_CORE) += tquic_core.o
tquic_core-y := \
	core/varint.o \
	core/connection.o \
	core/stream.o \
	core/frame.o \
	core/packet.o \
	core/ack.o \
	core/flow_control.o \
	core/transport_params.o \
	core/cid.o

# WAN Bonding components
obj-$(CONFIG_TQUIC_WAN_BONDING) += tquic_bond.o
tquic_bond-y := \
	bond/bonding.o

# Path Manager
obj-$(CONFIG_TQUIC_PATH_MANAGER) += tquic_pm.o
tquic_pm-y := \
	pm/path_manager.o

# Packet Scheduler
obj-$(CONFIG_TQUIC_SCHEDULER) += tquic_sched.o
tquic_sched-y := \
	sched/scheduler.o \
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

# Coupled congestion control for multipath
obj-$(CONFIG_TQUIC_WAN_BONDING) += tquic_coupled.o
tquic_coupled-y := cong/coupled.o

# Crypto support
obj-$(CONFIG_TQUIC_CRYPTO) += tquic_crypto.o
tquic_crypto-y := \
	crypto/tls.o \
	crypto/header_protection.o

# IPv6 Support
tquic-$(CONFIG_TQUIC_IPV6) += tquic_ipv6.o

# KUnit tests
obj-$(CONFIG_TQUIC_KUNIT_TEST) += tquic_test.o
tquic_test-y := \
	test/varint_test.o \
	test/packet_test.o \
	test/frame_test.o \
	test/flow_control_test.o \
	test/scheduler_test.o \
	test/transport_params_test.o
