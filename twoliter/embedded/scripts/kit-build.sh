#!/bin/bash
################################################################################
# kit-build.sh
#
# Build a kit from RPM packages.
#
# Required environment variables:
#   KIT - Kit name
#   ARCH - Target architecture
#   PACKAGE_DEPENDENCIES - Space-separated list of packages to include
#
# Optional environment variables:
#   BUILDER_UID - UID for output ownership (default: 1000)
#
# Expected mounts:
#   /src - Project root (ro)
#   /output - Output directory for kit (rw)
#   /rpms - RPM packages directory (ro)
################################################################################

set -euo pipefail

source /tools/scripts/common.sh

require_env KIT
require_env ARCH
require_env PACKAGE_DEPENDENCIES

BUILDER_UID="${BUILDER_UID:-1000}"

if ! rm -rf /output/*; then echo "Error cleaning output directory" >&2; exit 1; fi

# Build package arguments for rpm2kit
PACKAGE_ARGS=()
for pkg in "${PACKAGE_DEPENDENCIES}"; do
    PACKAGE_ARGS+=("--package=${pkg}")
done

# Run rpm2kit
if ! /src/build/tools/rpm2kit     --packages-dir=/rpms     --arch="${ARCH}"     "${PACKAGE_ARGS[@]}"     --output-dir=/output; then echo "Error running rpm2kit" >&2; exit 1; fi

set_output_ownership "${BUILDER_UID}" /output

echo "Kit build complete: ${KIT}"
