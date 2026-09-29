# Meizu MX6 · Linux 3.18.22

Kernel development for the **Meizu MX6 / M95 / M685 (MT6797)** and native
LineageOS 20 / Android 13. This branch extends the official
[Meizu M685 source](https://github.com/meizuosc/m685) with Mali Midgard r12p1,
legacy graphics ABI adaptations and Android compatibility changes.

**Project result:** a historical native Android 13 build (b23) completed boot,
LTE data and IMS registration on MX6. **This public source tip has not been
rebuilt and accepted on hardware.** The historical kernel and newer userspace
fixes must not be treated as one newly tested release.

## Hardware and source map

Selection is read from [`lineage_m95_defconfig`](arch/arm64/configs/lineage_m95_defconfig).
It describes requested options, not a freshly generated `.config` or proof that
every listed module was linked. A historical kernel build exists; individual
objects from this public tip have not been independently recompiled.

| Component | Source implementation | Defconfig selection | Compile / hardware status |
|---|---|---|---|
| 1080×1920 Sharp display | [FT8716 panel](drivers/misc/mediatek/lcm/ft8716_fhd_vdo_sharp/ft8716_fhd_vdo_sharp.c), [MT6797 DDP](drivers/misc/mediatek/video/mt6797/dispsys) | `MTK_LCM=y`, `CUSTOM_KERNEL_LCM=ft8716_fhd_vdo_sharp` | Source present; Not tested on this tip |
| Touchscreen | [FocalTech FT8716](drivers/input/touchscreen/mediatek/Mz_ft8716/focaltech_core.c) | `TOUCHSCREEN_FTS=y` | Original public driver retained; Not tested on this tip |
| GPU | [Mali Midgard r12p1](drivers/misc/mediatek/gpu/gpu_mali/mali_midgard/mali-r12p1) | `MTK_GPU_SUPPORT=y`, r12p1 selected | Kernel integration present; Graphics / power tests pending |
| Cameras | [IMX386 / OV5695 variants](drivers/misc/mediatek/imgsensor/src/mt6797) | Four sensor variants listed in `CUSTOM_KERNEL_IMGSENSOR` | Source present; frame delivery and camera lifecycle remain open |
| Audio / speaker amplifier | [MT6797 ASoC](sound/soc/mediatek/mt_soc_audio_6797), [ASoC codecs](sound/soc/codecs) | `MT_SND_SOC_6797=y`, `SND_SOC_TFA98XX=y` | Source selected; Call / media-route tests pending |
| Modem transport | [ECCCI / CLDMA](drivers/misc/mediatek/eccci) | `MTK_ECCCI_DRIVER=y`, `MTK_ECCCI_CLDMA=y` | LTE data and IMS registration observed in b23; call handling remains incomplete |
| Wi-Fi / Bluetooth | [MediaTek connectivity](drivers/misc/mediatek/connectivity) | `CONSYS_6797`, `MTK_COMBO_WIFI=y`, `MTK_BTIF=y` | Source selected; Radio / suspend tests pending |
| Charging / fuel gauge | [BQ2589x charger](drivers/misc/mediatek/power/mt6797/bq2589x_charger.c), [BQ27532 gauge](drivers/misc/mediatek/power/mt6797/bq27532_battery.c) | `MTK_BQ2589X_SUPPORT=y`, `BQ27532_BATTERY=y` | Source selected; Charging / thermal / suspend tests pending |
| Light / proximity | [APDS9922](drivers/input/apds9922), [BH1745](drivers/input/bh1745) | Both `INPUT_ALSPS_*` options enabled | Source selected; board-variant tests pending |
| Storage / USB | [MediaTek MMC](drivers/mmc/host/mediatek), [USB drivers](drivers/misc/mediatek/usb20) | `MMC_MTK=y`, `USB_MTK_DUALMODE=y`, `USB_MU3D_DRV=y` | Source selected; full I/O and USB-role regression tests pending |
| Android networking compatibility | [BPF implementation](kernel/bpf) | `BPF=y`, `BPF_SYSCALL=y`, `BPF_JIT=y` | Compatibility work present; Android networking tests pending |

IMS is implemented across modem firmware and Android userspace, not by ECCCI
alone. The b23 incoming-call crash was in the IMS service; its b24 userspace fix
was built but has no accepted device test. Outgoing VoLTE, SMS over IMS and
camera lifecycle still require testing.

## Building

Use `ARCH=arm64`, [`lineage_m95_defconfig`](arch/arm64/configs/lineage_m95_defconfig)
and an AArch64 Android GCC toolchain. Keep output in a separate Kbuild directory.
The stock-oriented [`mx6_defconfig`](arch/arm64/configs/mx6_defconfig) is also
retained; it is not the Android 13 configuration.

For an Android build, pair this kernel with the
[MX6 device tree](https://github.com/nomorecoolnicknames/android_device_meizu_m95-source/tree/lineage-20.0),
the matching framework compatibility changes and board-specific vendor inputs.
Kernel compilation alone does not assemble a ROM. ReMeizu build automation lives
in [build-infra](https://github.com/ReMeizu/build-infra); its current M5s job is
not an MX6 validation job.

## Credits and licensing

Based on [Meizu's M685 release](https://github.com/meizuosc/m685), Linux, MediaTek
and Arm driver work. Git history retains the downstream source contributions.
Keep [COPYING](COPYING) and all per-file copyright and license notices.
Proprietary firmware, calibration and Android vendor components are separate
inputs; source availability does not supply their redistribution rights.

[ReMeizu project status](https://github.com/nomorecoolnicknames/remeizu/blob/main/PROJECT_STATUS.md)
