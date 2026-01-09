use super::error::{self, Result};
use super::{ContainerRuntime, DockerRuntime, FinchRuntime, PodmanRuntime};
use std::sync::Arc;

/// Specifies which container runtime to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePreference {
    /// Automatically detect an available runtime (tries docker, finch, then podman).
    Auto,
    /// Use Docker explicitly.
    Docker,
    /// Use Finch explicitly.
    Finch,
    /// Use Podman explicitly.
    Podman,
}

/// Detects and returns a container runtime based on the given preference.
///
/// When `RuntimePreference::Auto` is specified, runtimes are tried in order:
/// docker, finch, then podman. The first available runtime is returned.
///
/// When a specific runtime is requested, only that runtime is checked.
/// Returns an error if the requested runtime is not available or fails version check.
///
/// # Errors
///
/// Returns `Error::NoRuntimeFound` if Auto detection finds no available runtime.
/// Returns runtime-specific errors if a requested runtime is unavailable or incompatible.
pub fn detect_runtime(preference: RuntimePreference) -> Result<Arc<dyn ContainerRuntime>> {
    match preference {
        RuntimePreference::Docker => {
            let rt = DockerRuntime::new();
            rt.check_version()?;
            Ok(Arc::new(rt))
        }
        RuntimePreference::Finch => {
            let rt = FinchRuntime::new();
            rt.check_version()?;
            Ok(Arc::new(rt))
        }
        RuntimePreference::Podman => {
            let rt = PodmanRuntime::new();
            rt.check_version()?;
            Ok(Arc::new(rt))
        }
        RuntimePreference::Auto => {
            if let Ok(docker) = try_docker() {
                return Ok(docker);
            }
            if let Ok(finch) = try_finch() {
                return Ok(finch);
            }
            if let Ok(podman) = try_podman() {
                return Ok(podman);
            }
            Err(error::Error::NoRuntimeFound)
        }
    }
}

fn try_docker() -> Result<Arc<dyn ContainerRuntime>> {
    let rt = DockerRuntime::new();
    rt.check_version()?;
    Ok(Arc::new(rt))
}

fn try_finch() -> Result<Arc<dyn ContainerRuntime>> {
    let rt = FinchRuntime::new();
    rt.check_version()?;
    Ok(Arc::new(rt))
}

fn try_podman() -> Result<Arc<dyn ContainerRuntime>> {
    let rt = PodmanRuntime::new();
    rt.check_version()?;
    Ok(Arc::new(rt))
}
