#!/bin/bash
set -euo pipefail

################################################################################
# package-build.sh
#
# Build an RPM package from a spec file.
################################################################################


source /tools/scripts/common.sh

require_env PACKAGE
require_env ARCH
require_env BUILD_ID
require_env BUILD_ID_TIMESTAMP

readonly BUILDER_UID="${BUILDER_UID:-1000}"
readonly WORKDIR="/home/builder"

cd "${WORKDIR}"

# Setup RPM macros - copy arch-specific macros to both locations
cp "/usr/lib/rpm/platform/${ARCH}-bottlerocket/macros" .rpmmacros
cp "/usr/lib/rpm/platform/${ARCH}-bottlerocket/macros" /root/.rpmmacros

# Prepare rpmbuild directories
mkdir -p rpmbuild/{SPECS,SOURCES,RPMS,BUILD}

# Copy spec file
cp "/src/packages/${PACKAGE}/${PACKAGE}.spec" rpmbuild/SPECS/${PACKAGE}.spec

# Copy package sources
find "/src/packages/${PACKAGE}" -maxdepth 1 -not -path '*/\.*' -type f -exec cp {} rpmbuild/SOURCES/ \;

# Copy RPMs (not symlink) for cross-mount compatibility with createrepo_c.
# createrepo_c fails with "Could not stat" or "Unable to read RPM header" when symlinks
# cross mount boundaries. In containers, /rpms is bind-mounted from host while rpmbuild/RPMS
# is on overlay fs - symlinks store absolute paths that fail to resolve across mount namespaces.
# This affects Docker/Podman/Finch equally (general bind-mount issue, not runtime-specific).
# Using cp -n creates real files on the same filesystem, avoiding symlink resolution entirely.
# Root level RPMs
find /rpms -mindepth 1 -maxdepth 1 -name '*.rpm' -size +0c -exec cp -n {} rpmbuild/RPMS/ \; 2>/dev/null || true

# Package dependency RPMs from subdirectories
for pkg in "${PACKAGE_DEPENDENCIES:-}"; do
    if [[ -d "/rpms/${pkg}" ]]; then
        find "/rpms/${pkg}/" -mindepth 1 -maxdepth 1 -name '*.rpm' -size +0c -exec cp -n {} rpmbuild/RPMS/ \; 2>/dev/null || true
    fi
done

# Also search recursively for any RPMs (maxdepth 2)
find /rpms -mindepth 2 -maxdepth 2 -name '*.rpm' -size +0c -exec cp -n {} rpmbuild/RPMS/ \; 2>/dev/null || true

# Create local repo
create_local_repo rpmbuild/RPMS rpmbuild/RPMS

# Build kit repo arguments
KIT_REPO_ARGS=""
if [[ -n "${KIT_DEPENDENCIES:-}" ]]; then
    KIT_REPO_ARGS=$(build_kit_repo_args "${ARCH}" ${KIT_DEPENDENCIES})
fi

EXTERNAL_KIT_REPO_ARGS=""
if [[ -n "${EXTERNAL_KIT_DEPENDENCIES:-}" ]]; then
    EXTERNAL_KIT_REPO_ARGS=$(build_external_kit_repo_args "${ARCH}" ${EXTERNAL_KIT_DEPENDENCIES})
fi

# Install build dependencies
dnf -y     --disablerepo '*'     --repofrompath repo,./rpmbuild/RPMS     --enablerepo 'repo'     ${KIT_REPO_ARGS}     ${EXTERNAL_KIT_REPO_ARGS}     --nogpgcheck     --forcearch "${ARCH}"     builddep rpmbuild/SPECS/${PACKAGE}.spec

# Setup cargo if vendor exists
if [[ -d /cargo-vendor ]]; then
    mkdir -p rpmbuild/.cargo
    cp /cargo-config rpmbuild/.cargo/config.toml 2>/dev/null || true
    ln -snf /cargo-vendor rpmbuild/.cargo/vendor
fi

# Link sources directory if it exists
if [[ -d /sources ]]; then
    ln -snf /sources rpmbuild/BUILD/sources
elif [[ -d /src/sources ]]; then
    ln -snf /src/sources rpmbuild/BUILD/sources
fi

# Setup cache
export HOME="${WORKDIR}"
mkdir -p "${WORKDIR}/.cache"
[[ -d /cache ]] && ln -snf /cache/* "${WORKDIR}/.cache/" 2>/dev/null || true

# Build the RPM
readonly DIST_TAG=".${BUILD_ID_TIMESTAMP}.${BUILD_ID//-dirty/}.br1"

rpmbuild -bb --clean     --undefine _auto_set_build_flags     --define "_target_cpu ${ARCH}"     --define "dist ${DIST_TAG}"     rpmbuild/SPECS/${PACKAGE}.spec

# Copy output RPMs
rm -rf /output/*
find rpmbuild/RPMS -name '*.rpm' -exec cp {} /output/ \;

# Set ownership
set_output_ownership "${BUILDER_UID}" /output

echo "Package build complete: ${PACKAGE}"
