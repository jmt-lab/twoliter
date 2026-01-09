#!/bin/bash
# Common functions for script-based builds
set -euo pipefail

# Ensure required environment variables are set
# Arguments: var - name of the environment variable to check
# Returns: exits 1 if variable is not set
require_env() {
    local var="$1"
    if [[ -z "${!var:-}" ]]; then
        echo "ERROR: Required environment variable ${var} is not set" >&2
        exit 1
    fi
}

# Setup RPM macros for the target architecture
# Arguments: arch - target architecture, workdir - working directory (default: /home/builder)
# Returns: exits 1 if macros file not found
setup_rpm_macros() {
    local arch="$1"
    local workdir="${2:-/home/builder}"
    local macros_file="/usr/lib/rpm/platform/${arch}-bottlerocket/macros"
    if [[ ! -f "${macros_file}" ]]; then
        echo "RPM macros file not found for architecture '${arch}': ${macros_file}" >&2
        exit 1
    fi
    cp "${macros_file}" "${workdir}/.rpmmacros"
}

# Create local RPM repository from existing RPMs
# Arguments: rpm_dir - directory containing RPMs, output_dir - destination for repository
# Returns: none
create_local_repo() {
    local rpm_dir="$1"
    local output_dir="$2"
    
    mkdir -p "${output_dir}"
    # Use flock to prevent parallel createrepo_c collisions when multiple build
    # processes share the same output directory (e.g., parallel CI jobs).
    # 120s timeout prevents indefinite hangs if lock holder crashes.
    (
        flock -w 120 9 || { echo "Failed to acquire createrepo lock" >&2; exit 1; }
        if ! createrepo_c \
            -o "${output_dir}" \
            -x '*-debuginfo-*.rpm' \
            -x '*-debugsource-*.rpm' \
            --no-database \
            "${rpm_dir}"; then
            echo "createrepo_c failed for ${rpm_dir}" >&2
            exit 1
        fi
    ) 9>"${output_dir}/.createrepo.lock"
}

# Build dnf repo arguments for kit dependencies
# Arguments: arch - target architecture, kits - array of kit names
# Returns: echoes repo arguments for dnf
build_kit_repo_args() {
    local arch="$1"
    shift
    local kits=("$@")
    
    local repo_args=()
    for kit in "${kits[@]}"; do
        [[ -z "${kit}" ]] && continue
        repo_args+=("--repofrompath=${kit},/kits/${kit}/${arch}" "--enablerepo=${kit}")
    done
    echo "${repo_args[@]}"
}

# Build dnf repo arguments for external kit dependencies
# Arguments: arch - target architecture, kits - array of external kit paths
# Returns: echoes repo arguments for dnf
build_external_kit_repo_args() {
    local arch="$1"
    shift
    local kits=("$@")
    
    local repo_args=()
    for kit in "${kits[@]}"; do
        [[ -z "${kit}" ]] && continue
        local repo_name="${kit//\//-}"
        repo_args+=("--repofrompath=${repo_name},/external-kits/${kit}/${arch}" "--enablerepo=${repo_name}")
    done
    echo "${repo_args[@]}"
}

# Set ownership of output files (non-fatal for user namespace compatibility)
# Arguments: uid - user ID to set ownership to, output_dir - directory to change ownership
# Returns: none (failures are silently ignored for rootless container compatibility)
set_output_ownership() {
    local uid="$1"
    local output_dir="$2"
    # chown may fail in rootless containers (user namespaces). This is defense-in-depth;
    # Rust-side fix_output_ownership() handles ownership via runtime-specific mechanisms.
    chown -R "${uid}:${uid}" "${output_dir}" 2>/dev/null || true
}
