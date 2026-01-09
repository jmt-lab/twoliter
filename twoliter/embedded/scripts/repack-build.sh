#!/bin/bash
################################################################################
# repack-build.sh
#
# Repack a Bottlerocket variant image to a different format.
#
# Required environment variables:
#   VARIANT - Variant name
#   ARCH - Target architecture
#   VERSION_ID - Version identifier
#   BUILD_ID - Build identifier
#   IMAGE_FORMAT - Output format (raw, qcow2, vmdk)
#   PARTITION_PLAN - Partition plan (split, unified)
#
# Image size configuration:
#   OS_IMAGE_SIZE_GIB - OS image size
#   DATA_IMAGE_SIZE_GIB - Data image size
#   OS_IMAGE_PUBLISH_SIZE_GIB - Published OS image size
#   DATA_IMAGE_PUBLISH_SIZE_GIB - Published data image size
#
# Feature flags (set to non-empty to enable):
#   UEFI_SECURE_BOOT, EROFS_ROOT_PARTITION, IN_PLACE_UPDATES
#
# Expected mounts:
#   /input - Input images directory (ro)
#   /output - Output directory (rw)
################################################################################

set -euo pipefail

source /tools/scripts/common.sh

main() {
    require_env VARIANT
    require_env ARCH
    require_env VERSION_ID
    require_env BUILD_ID
    require_env IMAGE_FORMAT

    local -r BUILDER_UID="${BUILDER_UID:-1000}"

    if [[ ! -x /src/build/tools/img2img ]]; then echo "Error: img2img not found" >&2; exit 1; fi

    # Build img2img arguments
    local IMG2IMG_ARGS=(
        --input-dir=/input
        --output-dir=/output
        --output-fmt="${IMAGE_FORMAT}"
        --os-image-size-gib="${OS_IMAGE_SIZE_GIB:-2}"
        --data-image-size-gib="${DATA_IMAGE_SIZE_GIB:-1}"
        --os-image-publish-size-gib="${OS_IMAGE_PUBLISH_SIZE_GIB:-2}"
        --data-image-publish-size-gib="${DATA_IMAGE_PUBLISH_SIZE_GIB:-1}"
        --partition-plan="${PARTITION_PLAN:-split}"
    )

    [[ -f "/src/variants/${VARIANT}/template.ovf" ]] && IMG2IMG_ARGS+=(--ovf-template="/src/variants/${VARIANT}/template.ovf")
    [[ -n "${EROFS_ROOT_PARTITION:-}" ]] && IMG2IMG_ARGS+=(--with-erofs-root-partition=yes)
    [[ -n "${IN_PLACE_UPDATES:-}" ]] && IMG2IMG_ARGS+=(--with-in-place-updates=yes)

    if ! /src/build/tools/img2img "${IMG2IMG_ARGS[@]}"; then echo "Error running img2img" >&2; exit 1; fi

    set_output_ownership "${BUILDER_UID}" /output
}

main "$@"
