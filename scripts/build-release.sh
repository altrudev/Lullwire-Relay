#!/usr/bin/env bash
# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build the relay for every supported platform, plus checksums:
#   ./scripts/build-release.sh            -> dist/lullwire-relay-<version>-<os>-<arch>[.exe], dist/SHA256SUMS
# The Android APK is built separately (android/build.sh) and its .apk can be copied
# into dist/ before running this, so SHA256SUMS covers it too.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(sed -n 's/^var version = "\(.*\)"/\1/p' cmd/lullwire-relay/main.go)"
OUT=dist
mkdir -p "$OUT"
targets=(
  linux/amd64 linux/arm64 linux/arm/7 linux/386
  windows/amd64 windows/arm64
  darwin/arm64 darwin/amd64
  freebsd/amd64 android/arm64
)
for t in "${targets[@]}"; do
  IFS=/ read -r os arch arm <<<"$t"
  name="lullwire-relay-$VERSION-$os-$arch${arm:+v$arm}"
  [[ $os == windows ]] && name+=".exe"
  GOOS=$os GOARCH=$arch GOARM=${arm:-} CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/$name" ./cmd/lullwire-relay
  echo "built $name"
done
(cd "$OUT" && rm -f SHA256SUMS && sha256sum -- * | grep -v ' SHA256SUMS$' > SHA256SUMS)
echo "checksums: $OUT/SHA256SUMS"
