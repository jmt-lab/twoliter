pub mod detect;
pub mod docker;
pub mod error;
pub mod finch;
pub mod podman;

pub use detect::{detect_runtime, RuntimePreference};
pub use docker::DockerRuntime;
pub use error::{Error, Result};
pub use finch::FinchRuntime;
pub use podman::PodmanRuntime;

use semver::Version;

/// Retry policy for container operations.
#[derive(Clone, Copy)]
pub enum RetryPolicy {
    /// No retry on failure.
    None,
    /// Retry build operations on failure.
    BuildRetry,
}
use std::collections::HashMap;
use std::process::Output;

/// Arguments for running a script inside a container.
#[derive(Debug, Clone, Default)]
pub struct ScriptBuildArgs {
    /// Container image to use.
    pub image: String,
    /// Script content to execute.
    pub script: String,
    /// Environment variables to set in the container.
    pub env: HashMap<String, String>,
    /// Volume mounts for the container.
    pub mounts: Vec<VolumeMount>,
    /// User to run as (e.g., "1000:1000").
    pub user: Option<String>,
    /// Working directory inside the container.
    pub workdir: Option<String>,
}

/// Arguments for building a container image.
#[derive(Debug, Clone, Default)]
pub struct BuildArgs {
    /// Build context directory path.
    pub context: String,
    /// Path to the Dockerfile.
    pub dockerfile: String,
    /// Build target stage name.
    pub target: String,
    /// Tag to apply to the built image.
    pub tag: String,
    /// Build arguments to pass (--build-arg).
    pub build_args: Vec<String>,
    /// Secret arguments to pass (--secret).
    pub secrets_args: Vec<String>,
    /// Build stages to skip cache for (--no-cache-filter).
    pub no_cache_filter: Vec<String>,
    /// Network mode for the build.
    pub network: String,
}

/// Represents a volume mount between host and container.
#[derive(Debug, Clone)]
pub struct VolumeMount {
    /// Host filesystem path.
    pub host: String,
    /// Container filesystem path.
    pub container: String,
    /// Whether the mount is read-only.
    pub readonly: bool,
}

/// Arguments for running a container.
#[derive(Debug, Clone, Default)]
pub struct RunArgs {
    /// Container image to run.
    pub image: String,
    /// Name to assign to the container.
    pub name: String,
    /// Volume mounts for the container.
    pub volumes: Vec<VolumeMount>,
    /// User to run as (e.g., "1000:1000").
    pub user: Option<String>,
    /// Run container in detached mode.
    pub detach: bool,
    /// Automatically remove container when it exits.
    pub rm: bool,
    /// Run an init process inside the container.
    pub init: bool,
    /// Network mode (e.g., "host", "none").
    pub net: Option<String>,
    /// PID namespace mode (e.g., "host").
    pub pid: Option<String>,
    /// Command and arguments to execute.
    pub command: Vec<String>,
}

/// Trait for container runtime implementations (Docker, Podman, Finch).
pub trait ContainerRuntime: Send + Sync {
    /// Returns the name of the runtime (e.g., "docker", "podman").
    fn name(&self) -> &'static str;
    
    /// Builds a container image from a Dockerfile.
    ///
    /// # Arguments
    /// * `args` - Build configuration including context, dockerfile, and tags.
    ///
    /// # Returns
    /// Command output on success, or an error.
    fn build(&self, args: &BuildArgs) -> Result<Output>;
    
    /// Runs a container with the specified configuration.
    ///
    /// # Arguments
    /// * `args` - Run configuration including image, volumes, and command.
    ///
    /// # Returns
    /// Command output on success, or an error.
    fn run(&self, args: &RunArgs) -> Result<Output>;
    
    /// Removes a container image.
    ///
    /// # Arguments
    /// * `image` - Image name or ID to remove.
    ///
    /// # Returns
    /// Command output on success, or an error.
    fn remove_image(&self, image: &str) -> Result<Output>;
    
    /// Removes a container.
    ///
    /// # Arguments
    /// * `container` - Container name or ID to remove.
    ///
    /// # Returns
    /// Command output on success, or an error.
    fn remove_container(&self, container: &str) -> Result<Output>;
    
    /// Returns the version of the container runtime.
    ///
    /// # Returns
    /// Semantic version on success, or an error.
    fn version(&self) -> Result<Version>;
    
    /// Checks if the runtime version meets minimum requirements.
    ///
    /// # Returns
    /// Ok if version is acceptable, error otherwise.
    fn check_version(&self) -> Result<()>;
    
    /// Runs a script inside a container.
    ///
    /// # Arguments
    /// * `args` - Script execution configuration including image and environment.
    ///
    /// # Returns
    /// Command output on success, or an error.
    fn run_script(&self, args: &ScriptBuildArgs) -> Result<Output>;
}
