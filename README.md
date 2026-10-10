# Pamn

Tauri 2 + React + TypeScript desktop GUI around nmap.

## Prerequisites
- Node 18+, Rust (stable), platform deps for Tauri 2: https://tauri.app/start/prerequisites/
- nmap, resolved in this order: bundled copy → custom path (`set_nmap_path`) → `PATH`.
  - Dev: `brew install nmap` (or apt/choco) is enough. To test the bundled path, copy the
    `nmap` binary and its data files (`nmap-services`, `nmap-os-db`, `nmap-service-probes`, `nselib/`, `scripts/`, …)
    into `src-tauri/resources/nmap/`. That folder is bundled and used as `NMAPDIR`.

## Run / build
```
npm install
npm run tauri dev     # window shows detected nmap version or "not found"
npm run build         # frontend typecheck + build
npm run tauri build   # packaged app
cd src-tauri && cargo check && cargo clippy
```

## Backend commands
`detect_nmap`, `set_nmap_path(path)`, `start_scan(args) -> id`, `cancel_scan(id)`.
Events: `scan-output {id, stream, line}` (stdout/stderr, incl. `--stats-every` progress), `scan-done {id, code, xml}`.
Args go straight to nmap as argv (no shell); `-o*` flags are rejected since the app owns `-oX`.

## Packaging / CI
`scripts/fetch-nmap.sh` downloads the official Nmap 7.991 build for the current OS into
`src-tauri/resources/nmap/` (macOS: x86_64 build, runs on Apple silicon via Rosetta; Windows: extracted
from the installer, Npcap is not bundled; Microsoft's x86 VC++ redistributable is kept and run silently by the installer if the runtime is missing; Linux: nothing bundled, the `.deb` depends on `nmap`).
`.github/workflows/build.yml` runs it and `tauri build` on macOS (arm64 + x64), Windows and Linux.
Bundled Nmap is NPSL and Npcap has its own license (non-commercial free edition) — see `THIRD_PARTY_NOTICES.md`.
Code signing/notarization is not configured.
