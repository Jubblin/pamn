# Third-party notices

This app is free and open source (MIT, see LICENSE) and redistributes unmodified
official builds of the following software, built from the official source tarball (macOS) or fetched (Windows) by `scripts/fetch-nmap.sh`.

## Nmap — https://nmap.org
Copyright (c) Nmap Software LLC. Licensed under the Nmap Public Source License
(NPSL), https://nmap.org/npsl/. Nmap is bundled unmodified and run as a separate
process. The full license and its bundled third-party licenses are shipped next to
the binary (`nmap/LICENSE`, `nmap/licenses/`). Source: https://nmap.org/dist/

## Npcap (Windows) — https://npcap.com
Pamn does **not** bundle or redistribute Npcap. Npcap's licence (https://npcap.com/oem/redist.html,
https://github.com/nmap/npcap/blob/master/LICENSE) allows the free edition only for personal/internal use
and requires a paid Npcap OEM licence to redistribute the installer inside a product; the free installer
also has no silent mode. So the Windows build strips Npcap from the Nmap installer contents, the Pamn
installer offers to open https://npcap.com/#download when Npcap is absent, and the app shows a
"Npcap is needed for scanning" banner with the same link. Each user downloads Npcap themselves under its licence.

## Microsoft Visual C++ Redistributable (Windows)
nmap.exe (32-bit) imports VCRUNTIME140.dll and MSVCP140.dll. Pamn bundles Microsoft's unmodified
`vc_redist.x86.exe` (taken from the official Nmap installer), which Microsoft permits applications to
redistribute under its redistributable licence terms, and the Pamn installer runs it silently only if the
x86 runtime is not already installed. If setup was skipped, the app shows a "Visual C++ runtime is missing" banner.

## Linux
A static Nmap built unmodified from the official source tarball by `scripts/fetch-nmap.sh` is bundled
(AppImage and .deb); no system nmap is needed.
