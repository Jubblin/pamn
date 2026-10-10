# Third-party notices

This app is free and open source (MIT, see LICENSE) and redistributes unmodified
official builds of the following software, fetched by `scripts/fetch-nmap.sh`.

## Nmap — https://nmap.org
Copyright (c) Nmap Software LLC. Licensed under the Nmap Public Source License
(NPSL), https://nmap.org/npsl/. Nmap is bundled unmodified and run as a separate
process. The full license and its bundled third-party licenses are shipped next to
the binary (`nmap/LICENSE`, `nmap/3rd-party-licenses.txt`). Source: https://nmap.org/dist/

## Npcap (Windows builds) — https://npcap.com
The Windows Nmap installer includes the Npcap packet-capture driver, licensed under
the Npcap license (https://npcap.com/oem/redist.html and https://github.com/nmap/npcap/blob/master/LICENSE).
Npcap's free license covers non-commercial use of the free edition only; commercial
redistribution requires an Npcap OEM license. Npcap's own license text is part of
its installer.

## Linux
No Nmap is bundled; the `.deb` declares a dependency on the distribution's `nmap`.
