#!/bin/bash
################################################################################
# variant-build.sh
#
# Build a Bottlerocket variant image.
#
# Required environment variables:
#   VARIANT - Variant name
#   ARCH - Target architecture
#   VERSION_ID - Version identifier
#   BUILD_ID - Build identifier
#   PACKAGES - Space-separated list of packages
#   PACKAGE_DEPENDENCIES - All package dependencies
#   KIT_DEPENDENCIES - Kit dependencies
#   EXTERNAL_KIT_DEPENDENCIES - External kit dependencies
#
# Image configuration:
#   IMAGE_FORMAT - Output format (raw, qcow2, vmdk)
#   OS_IMAGE_SIZE_GIB - OS image size
#   DATA_IMAGE_SIZE_GIB - Data image size
#   PARTITION_PLAN - Partition plan (split, unified)
#   OS_IMAGE_PUBLISH_SIZE_GIB - Published OS image size
#   DATA_IMAGE_PUBLISH_SIZE_GIB - Published data image size
#
# Feature flags (set to non-empty to enable):
#   UEFI_SECURE_BOOT, XFS_DATA_PARTITION, EROFS_ROOT_PARTITION
#   IN_PLACE_UPDATES, HOST_CONTAINERS, FIPS, ENCRYPTED_STORAGE
#   EXTERNAL_KMOD_DEVELOPMENT
#
# Expected mounts:
#   /src - Project root (ro)
#   /output - Output directory (rw)
#   /rpms - RPM packages (ro)
#   /kits - Kit repositories (ro)
#   /external-kits - External kit repositories (ro)
#   /sbkeys - Secure boot keys (ro, optional)
################################################################################

set -euo pipefail

source /tools/scripts/common.sh

require_env VARIANT
require_env ARCH
require_env VERSION_ID
require_env BUILD_ID
require_env PACKAGES

# Validate critical mount points
for mount in /rpms /kits /src; do
  [[ -d "${mount}" ]] || { echo "Required mount point missing: ${mount}" >&2; exit 1; }
done

BUILDER_UID="${BUILDER_UID:-1000}"
WORKDIR="/root"
cd "${WORKDIR}"

# Extract variant components
VARIANT_PLATFORM="${VARIANT_PLATFORM:-}"
VARIANT_RUNTIME="${VARIANT_RUNTIME:-}"
VARIANT_FAMILY="${VARIANT_FAMILY:-}"
VARIANT_FLAVOR="${VARIANT_FLAVOR:-}"

# Generate RPM macros
cat > generated.rpmmacros <<EOF
%_cross_variant ${VARIANT}
%_cross_variant_platform ${VARIANT_PLATFORM}
%_cross_variant_runtime ${VARIANT_RUNTIME}
%_cross_variant_family ${VARIANT_FAMILY}
%_cross_variant_flavor ${VARIANT_FLAVOR:-none}
%_topdir ${WORKDIR}/rpmbuild
EOF

# Generate bconds
cat > generated.bconds <<EOF
%bcond_without $(echo "${VARIANT_PLATFORM,,}" | tr '-' '_')_platform
%bcond_without $(echo "${VARIANT_RUNTIME,,}" | tr '-' '_')_runtime
%bcond_without $(echo "${VARIANT_FAMILY,,}" | tr '-' '_')_family
%bcond_without $(echo "${VARIANT_FLAVOR:-no}" | tr '[:upper:]-' '[:lower:]_')_flavor
EOF

[[ -n "${FIPS:-}" ]] && echo "%bcond_without fips" >> generated.bconds
[[ -n "${UEFI_SECURE_BOOT:-}" ]] && echo "%bcond_without uefi_secure_boot" >> generated.bconds
[[ -n "${XFS_DATA_PARTITION:-}" ]] && echo "%bcond_without xfs_data_partition" >> generated.bconds
[[ -n "${EROFS_ROOT_PARTITION:-}" ]] && echo "%bcond_without erofs_root_partition" >> generated.bconds
[[ -n "${IN_PLACE_UPDATES:-}" ]] && echo "%bcond_without in_place_updates" >> generated.bconds
[[ -n "${HOST_CONTAINERS:-}" ]] && echo "%bcond_without host_containers" >> generated.bconds
[[ -n "${EXTERNAL_KMOD_DEVELOPMENT:-}" ]] && echo "%bcond_without external_kmod_development" >> generated.bconds
[[ -n "${ENCRYPTED_STORAGE:-}" ]] && echo "%bcond_without encrypted_storage" >> generated.bconds

# Setup RPM macros
mkdir -p rpmbuild/SPECS rpmbuild/RPMS
cat "/usr/lib/rpm/platform/${ARCH}-bottlerocket/macros" generated.rpmmacros > .rpmmacros

# Build metadata RPM
cat generated.bconds /tools/metadata.spec > rpmbuild/SPECS/metadata.spec
echo "=== Building metadata RPM ===" >&2
echo "Contents of .rpmmacros:" >&2
cat .rpmmacros >&2
echo "=== End .rpmmacros ===" >&2
rpmbuild -ba --clean     --undefine _auto_set_build_flags     --define "_target_cpu ${ARCH}"     rpmbuild/SPECS/metadata.spec
echo "=== Metadata RPM build complete ===" >&2
echo "Looking for metadata RPMs:" >&2
find rpmbuild/RPMS -name '*metadata*' -ls >&2 || echo "No metadata RPMs found" >&2

# INVARIANT: createrepo_c requires all RPMs in a flat directory structure (no subdirectories).
# It cannot index RPMs in nested paths - all packages must be at the top level of the repo directory.
# Copy all required RPMs to flat directory for createrepo_c
find /rpms -name '*.rpm' -exec cp -n {} rpmbuild/RPMS/ \; 2>/dev/null || true
find rpmbuild/RPMS -mindepth 2 -name '*.rpm' -exec mv {} rpmbuild/RPMS/ \; 2>/dev/null || true

echo "=== RPMs in rpmbuild/RPMS before createrepo ===" >&2
ls -la rpmbuild/RPMS/*.rpm 2>&1 | head -20 >&2 || echo "No RPMs found" >&2
echo "=== Total RPM count: $(find rpmbuild/RPMS -maxdepth 1 -name '*.rpm' | wc -l) ===" >&2

# Create repo
create_local_repo rpmbuild/RPMS rpmbuild/RPMS

# Build repo arguments
KIT_REPO_ARGS=""
if [[ -n "${KIT_DEPENDENCIES:-}" ]]; then
    KIT_REPO_ARGS=$(build_kit_repo_args "${ARCH}" ${KIT_DEPENDENCIES})
fi

EXTERNAL_KIT_REPO_ARGS=""
if [[ -n "${EXTERNAL_KIT_DEPENDENCIES:-}" ]]; then
    EXTERNAL_KIT_REPO_ARGS=$(build_external_kit_repo_args "${ARCH}" ${EXTERNAL_KIT_DEPENDENCIES})
fi

# Download all required packages
mkdir -p /local/rpms /local/sbom-rpms
echo '%_dbpath %{_sharedstatedir}/rpm' >> /etc/rpm/macros

DOWNLOAD_PACKAGES=""
for pkg in metadata metadata-sbom ${PACKAGES}; do
    DOWNLOAD_PACKAGES="${DOWNLOAD_PACKAGES} bottlerocket-${pkg}"
done

dnf -y     --disablerepo '*'     --repofrompath repo,./rpmbuild/RPMS     --enablerepo 'repo'     ${KIT_REPO_ARGS}     ${EXTERNAL_KIT_REPO_ARGS}     --nogpgcheck     --forcearch "${ARCH}"     --setopt=cachedir=/local/rpms     install --downloadonly     ${DOWNLOAD_PACKAGES}

find /local/rpms -mindepth 2 -type f -name '*-sbom-*.rpm' -exec mv -t /local/sbom-rpms {} + 2>/dev/null || true
find /local/rpms -mindepth 2 -type f -name '*.rpm' -exec mv -t /local/rpms {} + 2>/dev/null || true
find /local/rpms -mindepth 1 ! -name '*.rpm' -delete 2>/dev/null || true

# Build image
rm -rf /output/*

RPM2IMG_ARGS=(
    --package-dir=/local/rpms
    --sbom-package-dir=/local/sbom-rpms
    --output-dir=/output
    --external-kits-path=/external-kits
    --output-fmt="${IMAGE_FORMAT:-raw}"
    --os-image-size-gib="${OS_IMAGE_SIZE_GIB:-2}"
    --data-image-size-gib="${DATA_IMAGE_SIZE_GIB:-1}"
    --os-image-publish-size-gib="${OS_IMAGE_PUBLISH_SIZE_GIB:-2}"
    --data-image-publish-size-gib="${DATA_IMAGE_PUBLISH_SIZE_GIB:-1}"
    --partition-plan="${PARTITION_PLAN:-split}"
)

[[ -f "/src/variants/${VARIANT}/template.ovf" ]] && RPM2IMG_ARGS+=(--ovf-template="/src/variants/${VARIANT}/template.ovf")
[[ -n "${XFS_DATA_PARTITION:-}" ]] && RPM2IMG_ARGS+=(--with-xfs-data-partition=yes)
[[ -n "${EROFS_ROOT_PARTITION:-}" ]] && RPM2IMG_ARGS+=(--with-erofs-root-partition=yes)
[[ -n "${UEFI_SECURE_BOOT:-}" ]] && RPM2IMG_ARGS+=(--with-uefi-secure-boot=yes)
[[ -n "${IN_PLACE_UPDATES:-}" ]] && RPM2IMG_ARGS+=(--with-in-place-updates=yes)
[[ -n "${ENCRYPTED_STORAGE:-}" ]] && RPM2IMG_ARGS+=(--with-encrypted-storage=yes)

# Copy sbkeys to writable location (p12 files are generated during signing)
if [[ -d /root/sbkeys ]]; then
    mkdir -p /tmp/sbkeys
    cp -a /root/sbkeys/* /tmp/sbkeys/ 2>/dev/null || true
    export SBKEYS=/tmp/sbkeys
fi

export VARIANT VERSION_ID BUILD_ID PRETTY_NAME IMAGE_NAME KERNEL_PARAMETERS
/src/build/tools/rpm2img "${RPM2IMG_ARGS[@]}"

# Build migrations if in-place updates enabled
if [[ -n "${IN_PLACE_UPDATES:-}" ]]; then
    mkdir -p /local/migrations
    find /rpms -maxdepth 2 -type f -name "bottlerocket-migrations-*.rpm" -not -iname '*debuginfo*' -exec cp {} /local/migrations/ \;
    /src/build/tools/rpm2migrations --package-dir=/local/migrations --output-dir=/output
    rm -rf /local/migrations
else
    mkdir -p "/output/${VERSION_ID}-${BUILD_ID}"
    touch "/output/${VERSION_ID}-${BUILD_ID}/.no-migrations"
fi

# Build kmod kit if external kmod development enabled
if [[ -n "${EXTERNAL_KMOD_DEVELOPMENT:-}" ]]; then
    mkdir -p /local/archives
    KERNEL="$(printf "%s
" "${PACKAGES}" | awk '/^kernel-/{print $1}')"
    find /rpms -type f -name "bottlerocket-${KERNEL}-archive-*.${ARCH}.rpm" -exec cp {} /local/archives/ \;
    /src/build/tools/rpm2kmodkit --archive-dir=/local/archives --toolchain-dir=/toolchain --output-dir=/output
    rm -rf /local/archives
else
    mkdir -p "/output/${VERSION_ID}-${BUILD_ID}"
    touch "/output/${VERSION_ID}-${BUILD_ID}/.no-kmod-kit"
fi

rm -rf /local/rpms
set_output_ownership "${BUILDER_UID}" /output

echo "Variant build complete: ${VARIANT}"
