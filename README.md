# Meizu MX6 kernel

Linux 3.18.22 for Meizu MX6 (M95/M685, MT6797), based on the
[Meizu M685 source](https://github.com/meizuosc/m685), with Mali Midgard r12p1
and Android 13 compatibility changes.

Use `arch/arm64/configs/lineage_m95_defconfig` with an AArch64 Android GCC
toolchain. Building an Android image also requires the matching device tree,
framework compatibility changes and separately supplied vendor components.
