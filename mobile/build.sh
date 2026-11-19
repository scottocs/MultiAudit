#!/bin/zsh
set -euo pipefail
cd "${0:A:h}/.."
platform="${1:-iphonesimulator}"
case "$platform" in
  iphonesimulator) triple=arm64-apple-ios17.0-simulator ;;
  iphoneos) triple=arm64-apple-ios17.0 ;;
  *) print -u2 'Use iphonesimulator or iphoneos'; exit 1 ;;
esac
sdk="$(xcrun --sdk "$platform" --show-sdk-path)"
compiler="$(xcrun --sdk "$platform" --find clang)"
mkdir -p "mobile/build/$platform"
env GOOS=ios GOARCH=arm64 CGO_ENABLED=1 GOCACHE=/private/tmp/multiaudit-ios-go-cache CC="$compiler" CGO_CFLAGS="-isysroot $sdk -target $triple" CGO_LDFLAGS="-isysroot $sdk -target $triple" go build -trimpath -buildmode=c-archive -o "mobile/build/$platform/libMultiAudit.a" ./mobile/bridge
