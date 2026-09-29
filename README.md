# Meizu MX6 · Linux 3.18.22 stock source

Original [Meizu M685](https://github.com/meizuosc/m685) kernel release for
**Meizu MX6 / M685 / MT6797**. This `master` branch
preserves the vendor baseline; Android 13 compatibility work lives in
[lineage-20.0](https://github.com/nomorecoolnicknames/android_kernel_meizu_m95/tree/lineage-20.0).
No custom-ROM or new hardware validation is claimed for this stock-source branch.

## Hardware and source map

Selection is read from [`mx6_defconfig`](arch/arm64/configs/mx6_defconfig).
It describes requested options, not a freshly generated `.config` or proof that
every listed module was linked. This source snapshot has not been independently rebuilt or tested here.

| Component | Source implementation | Defconfig selection | Compile / hardware status |
|---|---|---|---|
| 1080×1920 Sharp display | [FT8716 panel](drivers/misc/mediatek/lcm/ft8716_fhd_vdo_sharp/ft8716_fhd_vdo_sharp.c), [MT6797 DDP](drivers/misc/mediatek/video/mt6797/dispsys) | `MTK_LCM=y`, `CUSTOM_KERNEL_LCM=ft8716_fhd_vdo_sharp` | Source present; display not tested |
| Touchscreen | [FocalTech FT8716](drivers/input/touchscreen/mediatek/Mz_ft8716/focaltech_core.c) | `TOUCHSCREEN_FTS=y` | Original public driver retained; touch not tested |
| GPU | [Mali Midgard r7p0](drivers/misc/mediatek/gpu/gpu_mali/mali_midgard/mali-r7p0) | `MTK_GPU_SUPPORT=y`, r7p0 selected | Kernel integration present; full graphics and power validation pending |
| Cameras | [IMX386 / OV5695 variants](drivers/misc/mediatek/imgsensor/src/mt6797) | Four sensor variants listed in `CUSTOM_KERNEL_IMGSENSOR` | Source present; frame delivery and camera lifecycle remain open |
| Audio / speaker amplifier | [MT6797 ASoC](sound/soc/mediatek/mt_soc_audio_6797), [ASoC codecs](sound/soc/codecs) | `MT_SND_SOC_6797=y`, `SND_SOC_TFA98XX=y` | Source selected; complete call/media-route not tested |
| Modem transport | [ECCCI / CLDMA](drivers/misc/mediatek/eccci) | `MTK_ECCCI_DRIVER=y`, `MTK_ECCCI_CLDMA=y` | Stock transport code; not tested in this branch |
| Wi-Fi / Bluetooth | [MediaTek connectivity](drivers/misc/mediatek/connectivity) | `CONSYS_6797`, `MTK_COMBO_WIFI=y`, `MTK_BTIF=y` | Source selected; radio/suspend tests pending |
| Charging / fuel gauge | [BQ2589x charger](drivers/misc/mediatek/power/mt6797/bq2589x_charger.c), [BQ27532 gauge](drivers/misc/mediatek/power/mt6797/bq27532_battery.c) | `MTK_BQ2589X_SUPPORT=y`, `BQ27532_BATTERY=y` | Source selected; charging, thermal and suspend not tested |
| Light / proximity | [APDS9922](drivers/input/apds9922), [BH1745](drivers/input/bh1745) | Both `INPUT_ALSPS_*` options enabled | Source selected; board-variant tests pending |
| Storage / USB | [MediaTek MMC](drivers/mmc/host/mediatek), [USB drivers](drivers/misc/mediatek/usb20) | `MMC_MTK=y`, `USB_MTK_DUALMODE=y`, `USB_MU3D_DRV=y` | Source selected; full I/O and USB-role regression tests pending |

## Build inputs

Use the kernel in the repository root, `ARCH=arm64`, and an absolute
`CROSS_COMPILE` prefix for AArch64 Android GCC 4.9. Select
[mx6_defconfig](arch/arm64/configs/mx6_defconfig) and use a separate Kbuild output
directory. The BSP image target is `Image.gz-dtb`; matching MX6 board
generation inputs, ramdisk, command line and boot-image geometry are still
required for device integration. A kernel image alone is not a ROM.

No new build or device test was run for this source-map update. Use the matching
Android device tree and board firmware; a common chipset is not a substitute
for matching panel, touch, power and storage resources.

## Credits and licensing

Built on Linux, Android and MediaTek BSP work. Original vendor and downstream
authors remain credited in Git history and per-file notices. See
[COPYING](COPYING); individual files may carry additional terms.
Device firmware, calibration and Android vendor libraries are separate inputs.

[ReMeizu project status](https://github.com/nomorecoolnicknames/remeizu/blob/main/PROJECT_STATUS.md)
