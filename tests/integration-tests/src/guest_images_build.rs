use crate::twoliter_build::copy_project_to_temp_dir;
use std::path::Path;
use tempfile::TempDir;

use super::{run_command, test_projects_dir, TWOLITER_PATH};

/// Copy the `guest-images-kit` fixture to a temp directory and run `twoliter update`/`fetch`
/// so it is ready to build.
fn prepare_guest_images_kit() -> TempDir {
    let project = test_projects_dir().join("guest-images-kit");
    let tmp_dir = copy_project_to_temp_dir(&project);
    let project_path = tmp_dir.path().join("Twoliter.toml");
    let project_path_str = project_path.to_str().unwrap();

    let output = run_command(
        TWOLITER_PATH,
        ["update", "--project-path", project_path_str],
        [],
    );
    assert!(
        output.status.success(),
        "twoliter update failed for guest-images-kit"
    );

    let output = run_command(
        TWOLITER_PATH,
        ["fetch", "--project-path", project_path_str],
        [],
    );
    assert!(
        output.status.success(),
        "twoliter fetch failed for guest-images-kit"
    );

    tmp_dir
}

/// Returns the single per-version artifact directory under
/// `build/images/<arch>-<variant>/`, or `None` if no version directory yet exists.
fn variant_version_dir(
    project_root: &Path,
    arch: &str,
    variant: &str,
) -> Option<std::path::PathBuf> {
    let images_root = project_root.join(format!("build/images/{arch}-{variant}"));
    if !images_root.is_dir() {
        return None;
    }
    for entry in std::fs::read_dir(&images_root).ok()? {
        let entry = entry.ok()?;
        if entry.file_type().ok()?.is_dir() {
            return Some(entry.path());
        }
    }
    None
}

/// Build the host `wrapper-variant`. Cargo's build-dependency graph drives a build of the guest
/// `inner-variant` first, and during the host's image build the guest's image directory is
/// copied directly into the host rootfs. We assert here that:
///
///   1. The host variant build succeeds end-to-end.
///   2. The guest variant's image directory exists (proving the build-dependency triggered it).
///   3. The host variant's image directory exists and contains artifacts.
#[test]
#[ignore]
fn test_twoliter_build_variant_consumes_guest_images() {
    let tmp_dir = prepare_guest_images_kit();
    let project_path = tmp_dir.path().join("Twoliter.toml");
    let project_path_str = project_path.to_str().unwrap();

    let arch = "x86_64";

    let output = run_command(
        TWOLITER_PATH,
        [
            "build",
            "variant",
            "wrapper-variant",
            "--project-path",
            project_path_str,
            "--arch",
            arch,
        ],
        [],
    );
    assert!(
        output.status.success(),
        "twoliter build variant wrapper-variant failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The guest variant must have been built as a transitive build-dependency.
    let inner_dir = variant_version_dir(tmp_dir.path(), arch, "inner-variant")
        .expect("expected inner-variant images dir to exist after host build");
    assert!(
        std::fs::read_dir(&inner_dir).unwrap().next().is_some(),
        "no image artifacts produced for guest inner-variant under {}",
        inner_dir.display()
    );

    // The host variant should also have produced its own image dir with artifacts.
    let wrapper_dir = variant_version_dir(tmp_dir.path(), arch, "wrapper-variant")
        .expect("expected wrapper-variant images dir to exist after host build");
    assert!(
        std::fs::read_dir(&wrapper_dir).unwrap().next().is_some(),
        "no image artifacts produced for host wrapper-variant under {}",
        wrapper_dir.display()
    );
}
