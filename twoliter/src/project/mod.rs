mod lock;
pub(crate) mod vendor;

pub(crate) use self::vendor::ArtifactVendor;
pub(crate) use lock::VerificationTagger;

use self::lock::{Lock, LockedSDK, Override};
use crate::common::fs::{self, read_to_string};
use crate::compatibility::SUPPORTED_TWOLITER_PROJECT_SCHEMA_VERSION;
use crate::docker::ImageUri;
use crate::schema_version::SchemaVersion;
use anyhow::{ensure, Context, Result};
use async_recursion::async_recursion;
use async_trait::async_trait;
use async_walkdir::WalkDir;
use buildsys_config::{EXTERNAL_KIT_DIRECTORY, EXTERNAL_KIT_METADATA};
use futures::stream::StreamExt;
use semver::Version;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use toml::Table;
use tracing::{debug, info, instrument, trace, warn};

const TWOLITER_OVERRIDES: &str = "Twoliter.override";

/// Common functionality in commands, if the user gave a path to the `Twoliter.toml` file,
/// we use it, otherwise we search for the file. Returns the `Project` and the path at which it was
/// found (this is the same as `user_path` if provided).
#[instrument(level = "trace")]
pub(crate) async fn load_or_find_project(user_path: Option<PathBuf>) -> Result<Project<Unlocked>> {
    let project = match user_path {
        None => Project::find_and_load(".").await?,
        Some(p) => Project::load(&p).await?,
    };
    debug!(
        "Project file loaded from '{}'",
        project.filepath().display()
    );
    Ok(project)
}

/// Represents the structure of a `Twoliter.toml` project file.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Project<L: ProjectLock> {
    filepath: PathBuf,
    project_dir: PathBuf,

    /// The version of this schema struct.
    schema_version: SchemaVersion<SUPPORTED_TWOLITER_PROJECT_SCHEMA_VERSION>,

    /// The version that will be given to released artifacts such as kits and variants.
    release_version: String,

    /// The Bottlerocket SDK container image.
    sdk: Option<Image>,

    /// Set of vendors
    vendor: BTreeMap<ValidIdentifier, Vendor>,

    /// Set of kit dependencies
    kit: Vec<Image>,

    overrides: BTreeMap<String, BTreeMap<String, Override>>,

    /// The resolved and locked dependencies of the project.
    lock: L,
}

impl Project<Unlocked> {
    /// Load a `Twoliter.toml` file from the given file path (it can have any filename).
    pub(crate) async fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = fs::canonicalize(path).await?;
        let data = fs::read_to_string(&path)
            .await
            .context(format!("Unable to read project file '{}'", path.display()))?;
        let unvalidated: UnvalidatedProject = toml::from_str(&data).context(format!(
            "Unable to deserialize project file '{}'",
            path.display()
        ))?;
        let project = unvalidated.validate(path).await?;

        // When projects are resolved, tags are written indicating which artifacts have been checked
        // against the lockfile.
        // We clean these up as early as possible to avoid situations in which artifacts are
        // incorrectly flagged as having been resolved.
        VerificationTagger::cleanup_existing_tags(project.external_kits_dir()).await?;

        Ok(project)
    }

    /// Recursively search for a file named `Twoliter.toml` starting in `dir`. If it is not found,
    /// move up (i.e. `cd ..`) until it is found. Return an error if there is no parent directory.
    #[async_recursion]
    pub(crate) async fn find_and_load<P>(dir: P) -> Result<Self>
    where
        P: Send + AsRef<Path>,
    {
        let dir = dir.as_ref();
        trace!("Looking for Twoliter.toml in '{}'", dir.display());
        ensure!(
            dir.is_dir(),
            "Unable to locate Twoliter.toml in '{}': not a directory",
            dir.display()
        );
        let dir = dir
            .canonicalize()
            .context(format!("Unable to canonicalize '{}'", dir.display()))?;
        let filepath = dir.join("Twoliter.toml");
        if filepath.is_file() {
            return Self::load(&filepath).await;
        }
        // Move up a level and recurse.
        let parent = dir
            .parent()
            .context("Unable to find Twoliter.toml file")?
            .to_owned();
        Self::find_and_load(parent).await
    }

    pub(crate) async fn create_lock(self) -> Result<Project<Locked>> {
        let lock = Lock::create(&self).await?;
        Ok(self.with_new_lock(lock))
    }

    pub(crate) async fn load_lock<NL: ProjectLock>(&self) -> Result<Project<NL>> {
        VerificationTagger::cleanup_existing_tags(self.external_kits_dir()).await?;

        let resolved_lock = NL::load_lock(self, private::SealToken).await?;

        resolved_lock
            .verification_tagger(private::SealToken)
            .write_tags(self.external_kits_dir())
            .await?;

        Ok(self.with_new_lock(resolved_lock))
    }
}

impl<L: ProjectLock> Project<L> {
    /// Private function to create a new `Project` after resolving a different lock level.
    fn with_new_lock<NL: ProjectLock, T: Into<NL>>(&self, new_lock: T) -> Project<NL> {
        Project {
            filepath: self.filepath.clone(),
            project_dir: self.project_dir.clone(),
            schema_version: self.schema_version,
            release_version: self.release_version.clone(),
            sdk: self.sdk.clone(),
            vendor: self.vendor.clone(),
            kit: self.kit.clone(),
            overrides: self.overrides.clone(),
            lock: new_lock.into(),
        }
    }

    pub(crate) fn filepath(&self) -> PathBuf {
        self.filepath.clone()
    }

    pub(crate) fn project_dir(&self) -> PathBuf {
        self.project_dir.clone()
    }

    pub(crate) fn external_kits_dir(&self) -> PathBuf {
        self.project_dir.join(EXTERNAL_KIT_DIRECTORY)
    }

    pub(crate) fn external_kits_metadata(&self) -> PathBuf {
        self.project_dir.join(EXTERNAL_KIT_METADATA)
    }

    pub(crate) fn schema_version(&self) -> SchemaVersion<1> {
        self.schema_version
    }

    pub(crate) fn release_version(&self) -> &str {
        self.release_version.as_str()
    }

    pub(crate) fn direct_kit_deps(&self) -> Result<Vec<ProjectImage>> {
        self.kit
            .iter()
            .map(|kit| self.as_project_image(kit))
            .collect()
    }

    pub(crate) fn direct_sdk_image_dep(&self) -> Option<Result<ProjectImage>> {
        self.sdk.as_ref().map(|sdk| self.as_project_image(sdk))
    }

    pub(crate) fn vendor_for<V: VendedArtifact>(&self, artifact: &V) -> Option<ArtifactVendor> {
        let artifact_name = artifact.artifact_name();
        let vendor_name = artifact.vendor_name();
        let vendor = self.vendor.get(vendor_name)?;

        self.overrides
            .get(vendor_name.as_ref())
            .and_then(|vendor_overrides| vendor_overrides.get(artifact_name.as_ref()))
            .map(|override_| {
                ArtifactVendor::overridden(vendor_name.clone(), vendor.clone(), override_.clone())
            })
            .or(Some(ArtifactVendor::verbatim(
                vendor_name.clone(),
                vendor.clone(),
            )))
    }

    pub(crate) fn as_project_image<'proj, 'arti: 'proj>(
        &'proj self,
        image: &'arti impl VendedArtifact,
    ) -> Result<ProjectImage> {
        let vendor = self
            .vendor_for(image)
            .with_context(|| format!("Could not find defined vendor for image '{:?}'", &image))?;

        Ok(ProjectImage {
            image: Image::from_vended_artifact(image),
            vendor,
        })
    }

    /// Returns a list of the names of Go modules by searching the `sources` directory for `go.mod`
    /// files.
    pub(crate) async fn find_go_modules(&self) -> Result<Vec<String>> {
        let root = self.project_dir.join("sources");
        let mut entries = WalkDir::new(&root);
        let mut modules = Vec::new();
        loop {
            match entries.next().await {
                Some(Ok(entry)) => {
                    if let Some(filename) = entry.path().file_name() {
                        if filename == OsStr::new("go.mod") {
                            let parent_dir = entry
                                .path()
                                .parent()
                                .context(format!(
                                    "Expected the path '{}' to have a parent when searching for \
                                 go modules",
                                    entry.path().display()
                                ))?
                                .to_path_buf();

                            let module_name = parent_dir
                                .file_name()
                                .context(format!(
                                    "Expected to find a module name in path '{}'",
                                    parent_dir.display()
                                ))?
                                .to_str()
                                .context(format!(
                                    "Found non-UTF-8 character in file path '{}'",
                                    parent_dir.display(),
                                ))?
                                .to_string();
                            modules.push(module_name)
                        }
                    }
                }
                Some(Err(e)) => break Err(e).context("Error while searching for go modules"),
                None => break Ok(()),
            }
        }?;
        // Provide a predictable ordering.
        modules.sort();
        Ok(modules)
    }
}

impl Project<SDKLocked> {
    pub(crate) fn sdk_image(&self) -> ProjectImage {
        let SDKLocked(lock) = &self.lock;
        self.as_project_image(&lock.0)
            .expect("Could not find SDK vendor despite lock resolution succeeding?")
    }
}

impl Project<Locked> {
    /// Fetches all external kits defined in a Twoliter.lock to the build directory
    pub(crate) async fn fetch(&self, arch: &str) -> Result<()> {
        let Locked(lock) = &self.lock;
        lock.fetch(self, arch).await
    }

    #[expect(dead_code)]
    pub(crate) fn kits(&self) -> Vec<ProjectImage> {
        let Locked(lock) = &self.lock;
        lock.kit
            .iter()
            .map(|kit| self.as_project_image(kit))
            .collect::<Result<_>>()
            .expect("Could not find kit vendor despite lock resolution succeeding?")
    }

    pub(crate) fn sdk_image(&self) -> ProjectImage {
        let Locked(lock) = &self.lock;
        self.as_project_image(&lock.sdk)
            .expect("Could not find SDK vendor despite lock resolution succeeding?")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(crate) struct ProjectImage {
    image: Image,
    vendor: ArtifactVendor,
}

impl Display for ProjectImage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.vendor {
            ArtifactVendor::Overridden(_) => write!(
                f,
                "{}-{}@{} (overridden-to: {})",
                self.name(),
                self.version(),
                self.original_source_uri(),
                self.project_image_uri(),
            ),
            ArtifactVendor::Verbatim(_) => write!(
                f,
                "{}-{}@{}",
                self.name(),
                self.version(),
                self.original_source_uri()
            ),
        }
    }
}

impl ProjectImage {
    pub(crate) fn name(&self) -> &ValidIdentifier {
        &self.image.name
    }

    pub(crate) fn version(&self) -> &Version {
        self.image.version()
    }

    pub(crate) fn vendor_name(&self) -> &ValidIdentifier {
        self.vendor.vendor_name()
    }

    pub(crate) fn path_override(&self) -> Option<&String> {
        self.vendor.path_override()
    }

    /// Returns the URI for the original vendor.
    pub(crate) fn original_source_uri(&self) -> ImageUri {
        match &self.vendor {
            ArtifactVendor::Overridden(overridden) => {
                let original = ArtifactVendor::Verbatim(overridden.original_vendor());
                original.image_uri_for(&self.image)
            }
            ArtifactVendor::Verbatim(_) => self.vendor.image_uri_for(&self.image),
        }
    }

    /// Returns the image URI that the project will use for this image
    ///
    /// This could be different than the source_uri if overridden.
    pub(crate) fn project_image_uri(&self) -> ImageUri {
        ImageUri {
            registry: Some(self.vendor.registry().to_string()),
            repo: self.vendor.repo_for(&self.image).to_string(),
            tag: format!("v{}", self.image.version()),
        }
    }
}

/// An artifact/vendor name combination used to identify an artifact resolved by Twoliter.
///
/// This is intended for use in [`Project::vendor_for`] lookups.
pub(crate) trait VendedArtifact: std::fmt::Debug {
    fn artifact_name(&self) -> &ValidIdentifier;
    fn vendor_name(&self) -> &ValidIdentifier;
    fn version(&self) -> &Version;
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct ValidIdentifier(pub(crate) String);

impl Serialize for ValidIdentifier {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl FromStr for ValidIdentifier {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        ensure!(
            !input.is_empty(),
            "cannot define an identifier as an empty string",
        );

        // Check if the input contains any invalid characters
        for c in input.chars() {
            ensure!(
                is_valid_id_char(c),
                "invalid character '{}' found in identifier name",
                c
            );
        }

        Ok(Self(input.to_string()))
    }
}

impl<'de> Deserialize<'de> for ValidIdentifier {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;
        input.parse().map_err(D::Error::custom)
    }
}

impl AsRef<str> for ValidIdentifier {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl Display for ValidIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

fn is_valid_id_char(c: char) -> bool {
    match c {
        // Allow alphanumeric characters, underscores, and hyphens
        'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => true,
        // Disallow other characters
        _ => false,
    }
}

/// This represents a container registry vendor that is used in resolving the kits and also
/// now the bottlerocket sdk
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Vendor {
    pub registry: String,
}

/// This represents a dependency on a container, primarily used for kits
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Image {
    pub name: ValidIdentifier,
    pub version: Version,
    pub vendor: ValidIdentifier,
}

impl Image {
    fn from_vended_artifact(artifact: &impl VendedArtifact) -> Self {
        Self {
            name: artifact.artifact_name().clone(),
            vendor: artifact.vendor_name().clone(),
            version: artifact.version().clone(),
        }
    }
}

impl Display for Image {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}@{}", self.name, self.version, self.vendor)
    }
}

impl VendedArtifact for Image {
    fn artifact_name(&self) -> &ValidIdentifier {
        &self.name
    }

    fn vendor_name(&self) -> &ValidIdentifier {
        &self.vendor
    }

    fn version(&self) -> &Version {
        &self.version
    }
}

/// This is used to `Deserialize` a project, then run validation code before returning a valid
/// [`Project`]. This is necessary both because there is no post-deserialization serde hook for
/// validation and, even if there was, we need to know the project directory path in order to check
/// some things.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct UnvalidatedProject {
    schema_version: SchemaVersion<1>,
    release_version: String,
    sdk: Option<Image>,
    vendor: Option<BTreeMap<ValidIdentifier, Vendor>>,
    kit: Option<Vec<Image>>,
}

impl UnvalidatedProject {
    /// Constructs a [`Project`] from an [`UnvalidatedProject`] after validating fields.
    async fn validate(self, path: impl AsRef<Path>) -> Result<Project<Unlocked>> {
        let filepath: PathBuf = path.as_ref().into();
        let project_dir = filepath
            .parent()
            .context(format!(
                "Unable to find the parent directory of '{}'",
                filepath.display(),
            ))?
            .to_path_buf();

        self.check_vendor_availability().await?;
        self.check_release_toml(&project_dir).await?;
        let overrides = self.check_and_load_overrides(&project_dir).await?;

        Ok(Project {
            filepath,
            project_dir: project_dir.clone(),
            schema_version: self.schema_version,
            release_version: self.release_version,
            sdk: self.sdk,
            vendor: self.vendor.unwrap_or_default(),
            kit: self.kit.unwrap_or_default(),
            overrides,
            lock: Unlocked,
        })
    }

    /// Checks if an override file exists and if so loads it
    async fn check_and_load_overrides(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<BTreeMap<String, BTreeMap<String, Override>>> {
        let overrides_file_path = path.as_ref().join(TWOLITER_OVERRIDES);
        if !overrides_file_path.exists() {
            return Ok(BTreeMap::new());
        }
        info!("Detected override file, loading override information");
        let overrides_str = read_to_string(&overrides_file_path)
            .await
            .context("failed to read overrides file")?;
        let overrides: BTreeMap<String, BTreeMap<String, Override>> =
            toml::from_str(overrides_str.as_str())
                .context("failed to deserialize overrides file")?;
        Ok(overrides)
    }

    /// Errors if the user has defined a sdk and/or kit dependency without specifying the associated
    /// vendor
    async fn check_vendor_availability(&self) -> Result<()> {
        let mut dependency_list = self.kit.clone().unwrap_or_default();
        if let Some(sdk) = self.sdk.as_ref() {
            dependency_list.push(sdk.clone());
        }
        for dependency in dependency_list.iter() {
            ensure!(
                self.vendor.is_some()
                    && self
                        .vendor
                        .as_ref()
                        .unwrap()
                        .contains_key(&dependency.vendor),
                "cannot define a dependency on a vendor that is not specified in Twoliter.toml"
            );
        }
        Ok(())
    }

    /// Issues a warning if `Release.toml` is found and, if so, ensures that it contains the same
    /// version (i.e. `release-version`) as the `Twoliter.toml` project file.
    async fn check_release_toml(&self, project_dir: &Path) -> Result<()> {
        let path = project_dir.join("Release.toml");
        if !path.exists() || !path.is_file() {
            // There is no Release.toml file. This is a good thing!
            trace!("This project does not have a Release.toml file (this is not a problem)");
            return Ok(());
        }
        warn!(
            "A Release.toml file was found. Release.toml is deprecated. Please remove it from \
             your project."
        );
        let content = fs::read_to_string(&path).await.context(format!(
            "Error while checking Release.toml file at '{}'",
            path.display()
        ))?;
        let toml: Table = match toml::from_str(&content) {
            Ok(toml) => toml,
            Err(e) => {
                warn!(
                    "Unable to parse Release.toml to ensure that its version matches the \
                     release-version in Twoliter.toml: {e}",
                );
                return Ok(());
            }
        };
        let version = match toml.get("version") {
            Some(version) => version,
            None => {
                info!("Release.toml does not contain a version key. Ignoring it.");
                return Ok(());
            }
        }
        .as_str()
        .context("The version in Release.toml is not a string")?;
        ensure!(
            version == self.release_version,
            "The version found in Release.toml, '{version}', does not match the release-version \
            found in Twoliter.toml '{}'",
            self.release_version
        );
        Ok(())
    }
}

/// Marker trait that dictates what artifacts have been validated in the lock.
#[async_trait]
pub(crate) trait ProjectLock: Sized + Debug + Send + Sync + 'static {
    /// Loads the project lock for the given project.
    async fn load_lock(project: &Project<Unlocked>, _: private::SealToken) -> Result<Self>;

    /// Returns a `VerificationTagger` for this lock type.
    fn verification_tagger(&self, _: private::SealToken) -> VerificationTagger;
}

/// Indicates a project which has not resolved and validated the lockfile.
#[derive(Debug)]
pub struct Unlocked;

#[async_trait]
impl ProjectLock for Unlocked {
    async fn load_lock(_project: &Project<Unlocked>, _: private::SealToken) -> Result<Self> {
        Ok(Unlocked)
    }

    fn verification_tagger(&self, _: private::SealToken) -> VerificationTagger {
        VerificationTagger::no_verifications()
    }
}

/// Indicates a project which has resolved and verified only the SDK.
#[derive(Debug)]
pub struct SDKLocked(LockedSDK);

#[async_trait]
impl ProjectLock for SDKLocked {
    async fn load_lock(project: &Project<Unlocked>, _: private::SealToken) -> Result<Self> {
        LockedSDK::load(project).await.map(Self)
    }

    fn verification_tagger(&self, _: private::SealToken) -> VerificationTagger {
        (&self.0).into()
    }
}

impl From<LockedSDK> for SDKLocked {
    fn from(lock: LockedSDK) -> Self {
        SDKLocked(lock)
    }
}

/// Indicates a project which has resolved and verified all dependencies.
#[derive(Debug)]
pub struct Locked(Lock);

#[async_trait]
impl ProjectLock for Locked {
    async fn load_lock(project: &Project<Unlocked>, _: private::SealToken) -> Result<Self> {
        Lock::load(project).await.map(Self)
    }

    fn verification_tagger(&self, _: private::SealToken) -> VerificationTagger {
        (&self.0).into()
    }
}

impl From<Lock> for Locked {
    fn from(lock: Lock) -> Self {
        Locked(lock)
    }
}

/// Seal the `ProjectLock` trait -- only this module is allowed to define new lock types.
mod private {
    /// A marker type that, when used in a method signature, makes it impossible for other modules
    /// to implement the `ProjectLock` trait.
    pub struct SealToken;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::fs;
    use crate::test::{data_dir, projects_dir};
    use tempfile::TempDir;

    /// Ensure that `Twoliter.toml` can be deserialized.
    #[tokio::test]
    async fn deserialize_twoliter_1_toml() {
        let path = data_dir().join("Twoliter-1.toml");
        let deserialized = Project::load(path).await.unwrap();

        // Add checks here as desired to validate deserialization.
        assert_eq!(SchemaVersion::<1>, deserialized.schema_version);
        assert_eq!(1, deserialized.vendor.len());
        assert!(deserialized
            .vendor
            .contains_key(&ValidIdentifier("my-vendor".to_string())));
        assert_eq!(
            "a.com/b",
            deserialized
                .vendor
                .get(&ValidIdentifier("my-vendor".to_string()))
                .unwrap()
                .registry
        );

        let sdk = deserialized.sdk.unwrap();
        assert_eq!("my-bottlerocket-sdk", sdk.name.to_string());
        assert_eq!(Version::new(1, 2, 3), sdk.version);
        assert_eq!("my-vendor", sdk.vendor.to_string());

        assert_eq!(1, deserialized.kit.len());
        assert_eq!("my-core-kit", deserialized.kit[0].name.to_string());
        assert_eq!(Version::new(1, 2, 3), deserialized.kit[0].version);
        assert_eq!("my-vendor", deserialized.kit[0].vendor.to_string());
    }

    /// Ensure that a `Twoliter.toml` cannot be serialized if the `schema_version` is incorrect.
    #[tokio::test]
    async fn deserialize_invalid_version() {
        let path = data_dir().join("Twoliter-invalid-version.toml");
        let result = Project::load(path).await;
        let err = result.err().unwrap();
        let caused_by = err.source().unwrap().to_string();
        assert!(
            caused_by.contains("got '4294967295'"),
            "Expected the error message to contain \"got '4294967295'\", but the error message was this: {}",
            caused_by
        );
    }

    /// Ensure the `find_and_load` function searches upward until it finds `Twoliter.toml`.
    #[tokio::test]
    async fn find_and_deserialize_twoliter_1_toml() {
        let original_path = data_dir().join("Twoliter-1.toml");
        let tempdir = TempDir::new().unwrap();
        let twoliter_toml_path = tempdir.path().join("Twoliter.toml");
        let subdir = tempdir.path().join("a").join("b").join("c");
        fs::create_dir_all(&subdir).await.unwrap();
        fs::copy(&original_path, &twoliter_toml_path).await.unwrap();
        let project = Project::find_and_load(subdir).await.unwrap();

        // Ensure that the file we loaded was the one we expected to load.
        assert_eq!(project.filepath(), twoliter_toml_path);
    }

    #[tokio::test]
    async fn test_release_toml_check_error() {
        let tempdir = TempDir::new().unwrap();
        let p = tempdir.path();
        let from = data_dir();
        let twoliter_toml_from = from.join("Twoliter-1.toml");
        let twoliter_toml_to = p.join("Twoliter.toml");
        let release_toml_from = from.join("Release-2.toml");
        let release_toml_to = p.join("Release.toml");
        fs::copy(&twoliter_toml_from, &twoliter_toml_to)
            .await
            .unwrap();
        fs::copy(&release_toml_from, &release_toml_to)
            .await
            .unwrap();
        let result = Project::find_and_load(p).await;
        assert!(
            result.is_err(),
            "Expected the loading of the project to fail because of a mismatched version in \
            Release.toml, but the project loaded without an error."
        );
    }

    #[tokio::test]
    async fn test_verbatim_sdk() {
        let path = data_dir().join("Twoliter-1.toml");
        let project = Project::load(path).await.unwrap();

        let sdk = project.sdk.as_ref().unwrap();

        let vendor = project.vendor_for(sdk).unwrap();

        assert!(matches!(vendor, ArtifactVendor::Verbatim(_)));
    }

    #[tokio::test]
    async fn test_overridden_sdk() {
        let path = data_dir().join("override/Twoliter-override-1.toml");
        let project = Project::load(path).await.unwrap();

        let sdk = project.direct_sdk_image_dep().unwrap().unwrap();

        assert_eq!(
            &sdk.vendor,
            &ArtifactVendor::overridden(
                sdk.vendor_name().clone(),
                Vendor {
                    registry: "a.com/b".parse().unwrap(),
                },
                Override {
                    name: Some("my-overridden-sdk".parse().unwrap()),
                    registry: Some("c.com/d".parse().unwrap()),
                },
            )
        );

        assert_eq!(
            sdk.project_image_uri(),
            ImageUri {
                registry: Some("c.com/d".into()),
                repo: "my-overridden-sdk".into(),
                tag: "v1.2.3".into(),
            }
        )
    }

    #[tokio::test]
    async fn test_vendor_specifications() {
        let project = UnvalidatedProject {
            schema_version: SchemaVersion::default(),
            release_version: "1.0.0".into(),
            sdk: Some(Image {
                name: ValidIdentifier("bottlerocket-sdk".into()),
                version: Version::new(1, 41, 1),
                vendor: ValidIdentifier("bottlerocket".into()),
            }),
            vendor: Some(BTreeMap::from([(
                ValidIdentifier("not-bottlerocket".into()),
                Vendor {
                    registry: "public.ecr.aws/not-bottlerocket".into(),
                },
            )])),
            kit: Some(vec![Image {
                name: ValidIdentifier("bottlerocket-core-kit".into()),
                version: Version::new(1, 20, 0),
                vendor: ValidIdentifier("not-bottlerocket".into()),
            }]),
        };
        assert!(project.check_vendor_availability().await.is_err());
    }

    #[tokio::test]
    async fn test_release_toml_check_ok() {
        let tempdir = TempDir::new().unwrap();
        let p = tempdir.path();
        let from = data_dir();
        let twoliter_toml_from = from.join("Twoliter-1.toml");
        let twoliter_toml_to = p.join("Twoliter.toml");
        let release_toml_from = from.join("Release-1.toml");
        let release_toml_to = p.join("Release.toml");
        fs::copy(&twoliter_toml_from, &twoliter_toml_to)
            .await
            .unwrap();
        fs::copy(&release_toml_from, &release_toml_to)
            .await
            .unwrap();

        // The project should load because Release.toml and Twoliter.toml versions match.
        Project::find_and_load(p).await.unwrap();
    }

    #[tokio::test]
    async fn find_go_modules() {
        let twoliter_toml_path = projects_dir().join("project1").join("Twoliter.toml");
        let project = Project::load(twoliter_toml_path).await.unwrap();
        let go_modules = project.find_go_modules().await.unwrap();
        assert_eq!(go_modules.len(), 1, "Expected to find 1 go module");
        assert_eq!(go_modules.first().unwrap(), "hello-go");
    }
}
