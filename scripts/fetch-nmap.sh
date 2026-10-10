#!/usr/bin/env bash
# Populate src-tauri/resources/nmap with the official Nmap build for this OS.
# Linux: nothing bundled (the .deb depends on the distro's nmap; falls back to PATH).
set -euo pipefail
V=7.991
D="$(cd "$(dirname "$0")/.." && pwd)/src-tauri/resources/nmap"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
case "$(uname -s)" in
Darwin)
  curl -fsSL -o "$T/n.dmg" "https://nmap.org/dist/nmap-$V.dmg"
  hdiutil attach "$T/n.dmg" -mountpoint "$T/vol" -nobrowse -quiet
  pkgutil --expand-full "$T/vol/nmap-$V.mpkg" "$T/x"
  cp "$T/vol/LICENSE" "$T/vol/3rd-party-licenses.txt" "$T/" 2>/dev/null || true
  hdiutil detach "$T/vol" -quiet
  R="$T/x/nmap.pkg/Payload/nmap.app/Contents/Resources"
  rm -rf "$D"; mkdir -p "$D"
  cp "$R/bin/nmap" "$D/nmap"; cp -R "$R/lib" "$D/lib"; cp -R "$R/share/nmap/." "$D/"
  install_name_tool -add_rpath @executable_path/lib "$D/nmap"
  cp "$T/LICENSE" "$D/LICENSE" ; cp "$T/3rd-party-licenses.txt" "$D/"
  ;;
MINGW*|MSYS*|CYGWIN*)
  curl -fsSL -o "$T/n.exe" "https://nmap.org/dist/nmap-$V-setup.exe"
  7z x -y -o"$T/x" "$T/n.exe" >/dev/null
  rm -rf "$D"; mkdir -p "$D"
  cp -R "$T/x/." "$D/"
  rm -rf "$D/\$PLUGINSDIR" "$D/zenmap" "$D/uninstall.exe" "$D/ncat.exe" "$D/nping.exe" 2>/dev/null || true
  # Npcap installer ships inside the Nmap installer; kept so the app can offer to install it.
  ;;
*) echo "No bundled nmap for $(uname -s); using system nmap." ;;
esac
# keep the dir tracked
touch "$D/.gitkeep" 2>/dev/null || true
echo "nmap resources in $D"
