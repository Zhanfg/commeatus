#!/usr/bin/env bash
set -euo pipefail

ndk="${1:-${ANDROID_NDK_LATEST_HOME:-}}"
api="${2:-29}"

if [[ -z "$ndk" ]]; then
  echo "Android NDK path is required" >&2
  exit 1
fi

host="linux-x86_64"
toolchain="$ndk/toolchains/llvm/prebuilt/$host"
cc="$toolchain/bin/aarch64-linux-android${api}-clang"
ar="$toolchain/bin/llvm-ar"

if [[ ! -x "$cc" ]]; then
  echo "Android clang not found: $cc" >&2
  exit 1
fi
if [[ ! -x "$ar" ]]; then
  echo "Android llvm-ar not found: $ar" >&2
  exit 1
fi

# Cargo uses the linker variable for the final Rust binary. Native build
# scripts such as ring/cc-rs use the target-specific CC/AR variables instead.
# Keep both pointed at the exact same pinned NDK/API toolchain.
printf 'CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=%s\n' "$cc"
printf 'CC_aarch64_linux_android=%s\n' "$cc"
printf 'AR_aarch64_linux_android=%s\n' "$ar"
