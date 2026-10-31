#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo 'Run this installer using wsl -d Ubuntu-24.04 -u root -- bash ...' >&2
  exit 1
fi

task_setup_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
task_archive="$task_setup_dir/downloads/ipsw_3.1.739_linux_x86_64.tar.gz"
task_expected_sha=8124bdba7902e7627bae1bb2e1117c9cfcdc31de0f65ec55e341565ac6029a01
printf '%s  %s\n' "$task_expected_sha" "$task_archive" | sha256sum --check

export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=3 update
apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
  ca-certificates curl git build-essential cmake pkg-config fuse3 libfuse3-dev \
  zlib1g-dev libbz2-dev libattr1-dev file unzip python3

task_unpack_dir=$(mktemp -d /tmp/carplay-ipsw-install.XXXXXX)
tar -xzf "$task_archive" -C "$task_unpack_dir"
install -m 0755 "$task_unpack_dir/ipsw" /usr/local/bin/ipsw

task_source_dir=/opt/carplay-tools/src/apfs-fuse
mkdir -p /opt/carplay-tools/src
if [[ ! -d "$task_source_dir/.git" ]]; then
  git clone --recurse-submodules --depth 1 \
    https://github.com/sgan81/apfs-fuse.git "$task_source_dir"
fi
git -C "$task_source_dir" submodule update --init --recursive
cmake -S "$task_source_dir" -B "$task_source_dir/build" \
  -DCMAKE_BUILD_TYPE=Release -DUSE_FUSE3=ON
cmake --build "$task_source_dir/build" --parallel 4
cmake --install "$task_source_dir/build"
install -m 0755 "$task_source_dir/build/apfsutil" /usr/local/bin/apfsutil

mkdir -p /root/carplay /root/carplay/logs /root/carplay/output
test -c /dev/fuse
ipsw version
file /usr/local/bin/ipsw /usr/local/bin/apfs-fuse
git -C "$task_source_dir" rev-parse HEAD
git -C "$task_source_dir" submodule status
ls -l /dev/fuse
df -h / /root/carplay
printf '\nCarPlay analysis tools installed successfully.\n'
