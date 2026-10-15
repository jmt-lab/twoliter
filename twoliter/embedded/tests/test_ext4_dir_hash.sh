#!/usr/bin/env bash
#
# Tests `ext4_set_signed_dir_hash` in `imghelper`; skipped without e2fsprogs.
# Run from the repo root via `bash twoliter/embedded/tests/test_ext4_dir_hash.sh`.

set -eu -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMGHELPER="${SCRIPT_DIR}/../imghelper"

if [[ ! -f "${IMGHELPER}" ]]; then
  echo "test_ext4_dir_hash: imghelper not found at ${IMGHELPER}" >&2
  exit 1
fi

for tool in mkfs.ext4 debugfs dumpe2fs; do
  if ! command -v "${tool}" >/dev/null; then
    echo "test_ext4_dir_hash: ${tool} not found; skipping"
    exit 0
  fi
done

export IMAGE_NAME=test VARIANT=test ARCH=x86_64 VERSION_ID=1.0 BUILD_ID=0

# shellcheck source=../imghelper
. "${IMGHELPER}"

# Keep the timestamps debugfs and mkfs.ext4 write stable, as the image build does.
export SOURCE_DATE_EPOCH=1700000000 E2FSPROGS_FAKE_TIME=1700000000

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

pass_count=0
fail_count=0

pass() {
  pass_count=$((pass_count + 1))
  echo "  ok: $1"
}

fail() {
  fail_count=$((fail_count + 1))
  echo "  FAIL: $1" >&2
}

# Build an ext4 image of <dir> at <image> with fixed identifiers.
make_image() {
  local dir image
  dir="${1:?}"
  image="${2:?}"
  rm -f "${image}"
  mkfs.ext4 -q -b 4096 -U 3f0c9a64-2b1e-4c55-9d7a-6f3e1c2b8a90 \
    -E hash_seed=3f0c9a64-2b1e-4c55-9d7a-6f3e1c2b8a90 \
    -d "${dir}" "${image}" 8M
}

dir_hash_flags() {
  dumpe2fs -h "${1:?}" 2>/dev/null | sed -n 's/^Filesystem flags: *//p' | xargs
}

ASCII_DIR="${WORK_DIR}/ascii"
mkdir -p "${ASCII_DIR}/many"
for i in $(seq 1 200); do
  # Enough entries that the directory gets an htree index.
  : >"${ASCII_DIR}/many/settings-entry-${i}"
done
find "${ASCII_DIR}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

# Copied for each image: before e2fsprogs 1.47.1, `mkfs.ext4 -d` copies the
# tree's atimes, which reading it changes.
make_image "${ASCII_DIR}" "${WORK_DIR}/pristine.img"

###############################################################################
echo "Test 1: the flag is set to signed"
###############################################################################

cp "${WORK_DIR}/pristine.img" "${WORK_DIR}/a.img"
ext4_set_signed_dir_hash "${WORK_DIR}/a.img" "${ASCII_DIR}" >/dev/null 2>&1
flags="$(dir_hash_flags "${WORK_DIR}/a.img")"
if [[ "${flags}" == "signed_directory_hash" ]]; then
  pass "flags are '${flags}'"
else
  fail "expected 'signed_directory_hash', got '${flags}'"
fi

###############################################################################
echo "Test 2: images from either kind of host come out identical"
###############################################################################

# An image as an unsigned-char host writes it.
cp "${WORK_DIR}/pristine.img" "${WORK_DIR}/b.img"
echo "ssv flags 2" | debugfs -w -f - "${WORK_DIR}/b.img" >/dev/null 2>&1
ext4_set_signed_dir_hash "${WORK_DIR}/b.img" "${ASCII_DIR}" >/dev/null 2>&1
if cmp -s "${WORK_DIR}/a.img" "${WORK_DIR}/b.img"; then
  pass "images are byte-identical"
else
  fail "images differ: $(cmp "${WORK_DIR}/a.img" "${WORK_DIR}/b.img" 2>&1 || true)"
fi
if e2fsck -fn "${WORK_DIR}/b.img" >/dev/null 2>&1; then
  pass "e2fsck accepts the image"
else
  fail "e2fsck reports errors: $(e2fsck -fn "${WORK_DIR}/b.img" 2>&1 | head -5)"
fi

###############################################################################
echo "Test 3: names with non-ASCII bytes are refused"
###############################################################################

NON_ASCII_DIR="${WORK_DIR}/non-ascii"
mkdir -p "${NON_ASCII_DIR}"
: >"${NON_ASCII_DIR}/caf"$'\xc3\xa9'
make_image "${NON_ASCII_DIR}" "${WORK_DIR}/c.img"
cp "${WORK_DIR}/c.img" "${WORK_DIR}/c-before.img"
if ext4_set_signed_dir_hash "${WORK_DIR}/c.img" "${NON_ASCII_DIR}" >/dev/null 2>&1; then
  fail "ext4_set_signed_dir_hash accepted a non-ASCII name"
else
  pass "ext4_set_signed_dir_hash fails on a non-ASCII name"
fi
if cmp -s "${WORK_DIR}/c.img" "${WORK_DIR}/c-before.img"; then
  pass "the image is left unchanged"
else
  fail "the image was changed"
fi

###############################################################################
echo
echo "Results: ${pass_count} passed, ${fail_count} failed"
if [[ "${fail_count}" -gt 0 ]]; then
  exit 1
fi
