#!/usr/bin/env bash
# Populate src-tauri/resources/nmap with the official Nmap build for this OS.
# Linux: nothing bundled (the .deb depends on the distro's nmap; falls back to PATH).
set -euo pipefail
V=7.991
D="$(cd "$(dirname "$0")/.." && pwd)/src-tauri/resources/nmap"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
case "$(uname -s)" in
Darwin)
  # The official macOS installer is x86_64-only, so build nmap from the official source tarball
  # for the host arch (arm64 on Apple silicon, x86_64 on Intel). OpenSSL is linked statically;
  # everything else nmap bundles is static too, so the result is a single self-contained binary.
  command -v brew >/dev/null && brew list openssl@3 >/dev/null 2>&1 || brew install openssl@3
  SSL="$(brew --prefix openssl@3)"
  mkdir -p "$T/ossl/lib"; ln -s "$SSL/include" "$T/ossl/include"; ln -s "$SSL/lib/libssl.a" "$SSL/lib/libcrypto.a" "$T/ossl/lib/"
  curl -fsSL -o "$T/n.tar.bz2" "https://nmap.org/dist/nmap-$V.tar.bz2"
  tar xjf "$T/n.tar.bz2" -C "$T"
  (cd "$T/nmap-$V" && ./configure --prefix="$T/out" --with-openssl="$T/ossl" \
     --without-zenmap --without-ndiff --without-nping --without-ncat >/dev/null &&
   make -j"$(sysctl -n hw.ncpu)" >/dev/null && make install >/dev/null)
  rm -rf "$D"; mkdir -p "$D"
  cp "$T/out/bin/nmap" "$D/nmap"; cp -R "$T/out/share/nmap/." "$D/"
  cp "$T/nmap-$V/LICENSE" "$D/LICENSE"; cp -R "$T/nmap-$V/docs/licenses" "$D/licenses"
  file "$D/nmap"
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
