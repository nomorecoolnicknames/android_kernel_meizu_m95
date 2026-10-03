# Linux kernel for the Meizu MX6 (M95) — LineageOS 20

Linux 3.18 kernel for the Meizu MX6 (MediaTek MT6797 / Helio X20, model M95),
used for Android 13 / LineageOS 20.

## Origin

- Base: the kernel source released by Meizu under the GPL
  ([meizuosc/m685](https://github.com/meizuosc/m685)), the first commit of
  this branch.
- Changes for Android 13 on top of it: Mali Midgard r12p1 and display
  interfaces matching the vendor userspace, eBPF and other kernel features
  Android 13 requires, USB function filesystem and AIO, sdcardfs, Wi-Fi,
  camera flash, consumer IR, battery gauge and charger management, and fixes
  found during bring-up.
- Original authorship and copyright notices are kept. The kernel is licensed
  under the GPL version 2; see [COPYING](COPYING). Upstream notes are in
  [README](README).

Some driver parameters and log messages carry a `forge_` / `FORGE` prefix.
They are part of the interface used by the device configuration and are kept
as they are.

## Status

Android 13 runs as a daily system: display, touch, Wi-Fi (including the
hotspot), Bluetooth, mobile network, camera flash, sensors and charging work.
Suspend and long-run power management are still being verified.

## Building

Use the AOSP GCC 4.9 toolchain (`aarch64-linux-android-4.9`).

```sh
mkdir -p out
make O="$PWD/out" ARCH=arm64 CROSS_COMPILE=aarch64-linux-android- \
    HOSTCFLAGS=-fcommon m95_defconfig
make O="$PWD/out" ARCH=arm64 CROSS_COMPILE=aarch64-linux-android- \
    HOSTCFLAGS=-fcommon -j8 Image.gz-dtb
```

The board device tree is `arch/arm64/boot/dts/meizu6797_6c_m_flat.dts`, a
self-contained tree that already includes the generated board pin data, so
no DCT tool is needed. `mx6_defconfig` is the original Meizu configuration.

## Not included

- Prebuilt binaries of the Meizu release: the DCT tool and its Qt libraries,
  firmware images and documentation images.

No kernel image, proprietary firmware, signing key or device identity is
included.
