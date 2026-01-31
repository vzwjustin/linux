# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_QUIC) += quic.o

quic-y := \
	protocol.o \
	connection.o \
	stream.o \
	packet.o \
	crypto.o \
	socket.o

quic-$(CONFIG_TQUIC) += \
	tquic_path.o \
	tquic_scheduler.o \
	tquic_netlink.o
