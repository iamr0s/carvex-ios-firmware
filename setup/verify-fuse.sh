#!/usr/bin/env bash
set -euo pipefail

task_test_dir=$(mktemp -d /tmp/carplay-fuse-check.XXXXXX)
task_mount_dir="$task_test_dir/mount"
mkdir "$task_mount_dir"
task_cleanup() {
  if mountpoint -q "$task_mount_dir"; then
    umount "$task_mount_dir"
  fi
}
trap task_cleanup EXIT

test -c /dev/fuse
curl --fail --location --retry 3 --connect-timeout 15 --max-time 90 \
  https://raw.githubusercontent.com/libfuse/libfuse/fuse-3.14.0/example/hello.c \
  --output "$task_test_dir/hello.c"
cc -Wall -O2 "$task_test_dir/hello.c" -o "$task_test_dir/hello-fuse" \
  $(pkg-config fuse3 --cflags --libs)
"$task_test_dir/hello-fuse" "$task_mount_dir"
mountpoint -q "$task_mount_dir"
test "$(cat "$task_mount_dir/hello")" = 'Hello World!'
umount "$task_mount_dir"
if mountpoint -q "$task_mount_dir"; then
  echo 'FUSE test left a mounted filesystem.' >&2
  exit 1
fi
printf 'PASS: FUSE mount, read, and umount succeeded.\n'
