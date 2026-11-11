#!/bin/sh
# Build the plugin, and make the directory that the IDA Plugin Manager installs:
# ida-plugin.json, the README, and the library by the name of the entry point.
#
# usage: package.sh <platform> <directory>
#
# The platform is that of the build, by its name in ida-plugin.json, like linux-x86_64.
set -eu

platform=$1
out=$2
here=$(cd "$(dirname "$0")" && pwd)

case "$platform" in
    linux-*)   library=libfloss_ida.so ;;
    macos-*)   library=libfloss_ida.dylib ;;
    windows-*) library=floss_ida.dll ;;
    *) echo "error: unknown platform: $platform" >&2; exit 1 ;;
esac

cargo build --manifest-path "$here/Cargo.toml" --profile dist --locked

mkdir -p "$out"
jq --arg platform "$platform" '.plugin.platforms = [$platform]' "$here/ida-plugin.json" > "$out/ida-plugin.json"
cp "$here/README.md" "$out/README.md"
cp "${CARGO_TARGET_DIR:-$here/target}/dist/$library" "$out/floss_ida.${library##*.}"
