#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: package-alpha.sh <version> <git-sha> [android-ndk]}"
git_sha="${2:?usage: package-alpha.sh <version> <git-sha> [android-ndk]}"
android_ndk="${3:-unknown}"

linux_binary="target/release/commeatus"
android_binary="target/aarch64-linux-android/release/commeatus"

test -x "$linux_binary"
test -f "$android_binary"

linux_dir="commeatus-$version-linux-x86_64"
android_dir="commeatus-$version-android-arm64"

rm -rf staging dist
mkdir -p "staging/$linux_dir" "staging/$android_dir" dist

cp "$linux_binary" "staging/$linux_dir/commeatus"
cp "$android_binary" "staging/$android_dir/commeatus"
for dir in "$linux_dir" "$android_dir"; do
  cp LICENSE README.md CHANGELOG.md "staging/$dir/"
  cp examples/commeatus.conf "staging/$dir/"
done

{
  echo "version=$version"
  echo "git_sha=$git_sha"
  echo "rustc=$(rustc +stable --version)"
  echo "runner=${RUNNER_OS:-local}/${RUNNER_ARCH:-unknown}"
} > "staging/$linux_dir/BUILD-INFO.txt"
cp "staging/$linux_dir/BUILD-INFO.txt" "staging/$android_dir/BUILD-INFO.txt"
echo "android_ndk=$android_ndk" >> "staging/$android_dir/BUILD-INFO.txt"
echo "android_min_api=29" >> "staging/$android_dir/BUILD-INFO.txt"

tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C staging -cf - "$linux_dir" | gzip -n > "dist/$linux_dir.tar.gz"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C staging -cf - "$android_dir" | gzip -n > "dist/$android_dir.tar.gz"

(
  cd dist
  sha256sum *.tar.gz > SHA256SUMS
  sha256sum -c SHA256SUMS
)

# Ask tar for the exact members instead of piping a full listing into grep -q.
# Under `set -o pipefail`, grep's early exit would close the pipe and make tar
# report SIGPIPE even when the member was present.
tar -tzf "dist/$linux_dir.tar.gz" "$linux_dir/commeatus" >/dev/null
tar -tzf "dist/$android_dir.tar.gz" "$android_dir/commeatus" >/dev/null
tar -tzf "dist/$linux_dir.tar.gz" "$linux_dir/commeatus.conf" >/dev/null
tar -tzf "dist/$android_dir.tar.gz" "$android_dir/BUILD-INFO.txt" >/dev/null
