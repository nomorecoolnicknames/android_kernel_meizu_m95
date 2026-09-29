# ReMeizu MX6 / M95 — Android 13 kernel development

Linux 3.18.22 with MT6797 board work, Mali r12p1 integration and Android 13 compatibility changes.

Native LineageOS 20 userdebug has booted on MX6; historical device testing
observed LTE data and IMS registration. Remaining work includes incoming IMS
call handling, camera lifecycle and full power/suspend acceptance. This is
active development, not a stable-ROM release.

- [Source provenance, exclusions and build requirements](PUBLICATION.md)
- [Original-to-public commit history](PUBLICATION.json)
- [Verified historical runtime and artifact identities](RUNTIME_SUMMARY.json)
- [ReMeizu project progress](https://github.com/nomorecoolnicknames/remeizu/blob/codex/progress-and-roadmap-20260929/PROJECT_STATUS.md)

This publication performs no new build or hardware test and does not supply
a complete proprietary-free Android build environment. Existing source licenses
apply per file; see the publication notes before selecting hosted build inputs.
