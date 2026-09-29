# Meizu MX6 / M95 — Android 13 kernel development source

This branch publishes the Linux 3.18.22 development baseline corresponding to
the project's native Android 13 bring-up: Mali Midgard r12p1 integration,
legacy graphics ABI adaptations, BPF/filesystem compatibility work and board
configuration. It descends from the original public
[Meizu M685 source](https://github.com/meizuosc/m685/commit/b3b275a55d62afd3006604ec05a9cb5fc674c692).

Original source checkpoint: `3522613e6f22a947ddf2282e636b165b2ce6c4c3`.
The retained ROM boot image embeds kernel
`3.18.22-eng-g78e751a9-dirty #145` from 13 September. Existing build forensics
identify its dirty source change as the host-linker fix subsequently committed
in `3522613e`. Publication does not claim a new bit-for-bit rebuild.

One private logging-only change in
`drivers/input/touchscreen/mediatek/Mz_ft8716/focaltech_core.c` is withheld
because of its restrictive file notice: this branch retains the exact original
already-public upstream file. That difference is recorded, so this publication
is **not byte-identical to all development inputs**. The rest of the imported
source changes are preserved byte-for-byte. The inherited upstream BSP already
contains vendor material and is not asserted to be wholly blob-free or eligible
for an unrestricted OSL build. New private binaries/logs are not published.

Later perf2/perf3 branches are separate experiments and are not silently
substituted for the kernel baseline identified by the ROM build records.

## Demonstrated Android 13 result

MX6 has progressed beyond the earlier GSI experiments: native LineageOS 20
userdebug build 23 booted on the device. The retained 26 September 2026 capture
reports Android 13, SDK 33, `20.0-20260925-UNOFFICIAL-m95` and
`sys.boot_completed=1`. LTE data and IMS registration were observed. Incoming
IMS calls still crashed the IMS service; the fix was built in build 24 but
has not been accepted on hardware. Outgoing VoLTE, SMS over IMS, camera
lifecycle/frame delivery and full power/suspend testing remain open.

The compact [runtime summary](RUNTIME_SUMMARY.json) records source/artifact
identity and the hashes of retained private evidence. Raw logs contain device
and subscriber data and are intentionally not published. This publication
performed no new build, flash, readback or device test. Historical flash logs
are not a fresh partition-readback result.

## History, licensing and reproducibility

`PUBLICATION.json` maps every imported original commit to the filtered public
commit, with exclusions and redactions. Original authors, dates, parent graph
and commit subjects are retained; operational commit bodies are replaced by
source provenance. Original private repositories and active working trees
are unchanged. Existing per-file licenses and copyright notices remain;
public visibility is not a blanket license grant or an OSL eligibility review.

Full Android builds also need framework/compatibility changes, a matching
kernel configuration/toolchain, and separately supplied vendor components.
The device/kernel branches are reviewable source checkpoints, not a complete
proprietary-free ROM manifest. Missing inputs are not replaced with stubs or
allow-missing build flags. OSL work must use a separately reviewed complete
open-source input set; proprietary ROM builds/storage remain outside it.
