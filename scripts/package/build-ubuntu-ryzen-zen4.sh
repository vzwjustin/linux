#!/usr/bin/env bash
# Build a Zen 4 (Ryzen 7000) tuned kernel as Ubuntu .deb packages.
#
# Run from the kernel source root on the target box (Ubuntu 26.04, 7950X):
#   sudo apt install build-essential bc kmod cpio flex bison libssl-dev \
#                    libelf-dev libncurses-dev dwarves zstd debhelper rsync
#   scripts/package/build-ubuntu-ryzen-zen4.sh
#
# Result: ../linux-image-*-zen4_*.deb (+ headers, libc-dev). Install with
#   sudo dpkg -i ../linux-{image,headers}-*-zen4_*.deb
#   sudo update-grub
#
# Env knobs:
#   JOBS=N         override parallelism (default: nproc)
#   BASE_CONFIG=…  path to base .config (default: /boot/config-$(uname -r))
#   LOCALVERSION=… suffix on uname -r (default: -zen4)

set -euo pipefail

JOBS="${JOBS:-$(nproc)}"
LOCALVERSION="${LOCALVERSION:--zen4}"
BASE_CONFIG="${BASE_CONFIG:-/boot/config-$(uname -r)}"

cd "$(dirname "$0")/../.."
SRC="$PWD"

if [[ ! -f "$BASE_CONFIG" ]]; then
	echo "Base config $BASE_CONFIG not found; falling back to 'make defconfig'." >&2
	make defconfig
else
	cp "$BASE_CONFIG" .config
fi

# Ubuntu's running config references signing keys that aren't shipped — strip
# them so a self-signed build doesn't fail. Re-enable manually if you sign.
# LOCALVERSION is passed to make below; setting it here too would concat and
# produce e.g. "-zen4-zen4" in uname -r.
scripts/config \
	--set-str SYSTEM_TRUSTED_KEYS "" \
	--set-str SYSTEM_REVOCATION_KEYS "" \
	--disable MODULE_SIG_ALL

# Resolve any new symbols introduced since the base config, then layer the
# Zen 4 fragment on top.
make olddefconfig
KCONFIG_CONFIG=.config scripts/kconfig/merge_config.sh -m \
	.config kernel/configs/ryzen-zen4.config
make olddefconfig

echo
echo "==> Building Zen 4 kernel with -j$JOBS (LOCALVERSION=$LOCALVERSION)"
make -j"$JOBS" bindeb-pkg LOCALVERSION="$LOCALVERSION"

echo
echo "==> Built packages:"
ls -1 ../linux-*"$LOCALVERSION"*.deb 2>/dev/null || true
echo
echo "Install with:"
echo "    sudo dpkg -i ../linux-image-*${LOCALVERSION}_*.deb \\"
echo "                 ../linux-headers-*${LOCALVERSION}_*.deb"
echo "    sudo update-grub"
