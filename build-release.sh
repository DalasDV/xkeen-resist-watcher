#!/bin/sh
set -eu

VERSION=${1:?Usage: sh build-release.sh vVERSION [output-directory]}
OUTPUT=${2:-dist}
case "$VERSION" in
    *[!a-zA-Z0-9._-]*) echo 'Invalid release version.' >&2; exit 1 ;;
esac
mkdir -p "$OUTPUT"

build() {
    suffix=$1
    shift
    env GOOS=linux CGO_ENABLED=0 "$@" go build -trimpath \
        -ldflags="-s -w -X main.version=$VERSION" \
        -o "$OUTPUT/xkeen-subscription-watcher-linux-$suffix" .
}

build arm64 GOARCH=arm64
build armv7 GOARCH=arm GOARM=7
build mipsel GOARCH=mipsle GOMIPS=softfloat
build mips GOARCH=mips GOMIPS=softfloat

(
    cd "$OUTPUT"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum xkeen-subscription-watcher-linux-*
    else
        shasum -a 256 xkeen-subscription-watcher-linux-*
    fi > SHA256SUMS
)
