//! Compare a rebuilt disk image against the image published in an AMI.

use crate::disk::{self, DiskLayout, Policy, RangeHash};
use crate::error::Result;
use crate::fsfiles::FileReport;
use serde::Serialize;
use snafu::ResultExt;
use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Match,
    Mismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Verified,
    Failed,
}

/// The result of comparing one region of the disk.
#[derive(Debug, Clone, Serialize)]
pub struct RegionReport {
    pub name: String,
    pub policy: Policy,
    pub status: Status,
    /// Whether a mismatch in this region fails verification.
    pub fatal: bool,
    pub offset: u64,
    pub len: u64,
    pub expected_sha256: Option<String>,
    pub actual_sha256: Option<String>,
    pub detail: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileReport>,
}

impl RegionReport {
    fn failed(&self) -> bool {
        self.fatal && self.status == Status::Mismatch
    }
}

/// The result of comparing one disk image.
#[derive(Debug, Clone, Serialize)]
pub struct ImageReport {
    pub expected: Option<PathBuf>,
    pub actual: Option<PathBuf>,
    pub expected_len: u64,
    pub actual_len: u64,
    pub regions: Vec<RegionReport>,
}

impl ImageReport {
    fn failed(&self) -> bool {
        self.regions.iter().any(RegionReport::failed)
    }
}

/// The full comparison report.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub verdict: Verdict,
    pub os: ImageReport,
    pub data: Option<ImageReport>,
    pub notes: Vec<String>,
}

const NOTES: &[&str] = &[];

struct Images {
    expected: File,
    actual: File,
}

impl Images {
    fn open(expected: &Path, actual: &Path) -> Result<Self> {
        let open =
            |p: &Path| File::open(p).whatever_context(format!("failed to open {}", p.display()));
        Ok(Self {
            expected: open(expected)?,
            actual: open(actual)?,
        })
    }

    fn hash(&mut self, ranges: &[(u64, u64)]) -> Result<(RangeHash, RangeHash)> {
        Ok((
            disk::hash_ranges(&mut self.expected, ranges)?,
            disk::hash_ranges(&mut self.actual, ranges)?,
        ))
    }
}

fn region(
    name: &str,
    policy: Policy,
    ranges: &[(u64, u64)],
    expected: Option<&RangeHash>,
    actual: &RangeHash,
) -> RegionReport {
    let offset = ranges.first().map(|r| r.0).unwrap_or(0);
    let len = ranges.iter().map(|r| r.1).sum();
    let identical = expected.is_none_or(|e| e == actual);
    let (status, detail) = match policy {
        Policy::MustBeZero if !actual.all_zero => {
            (Status::Mismatch, "published image is not all zero")
        }
        _ if identical => (Status::Match, "identical"),
        _ => (Status::Mismatch, "contents differ"),
    };
    RegionReport {
        name: name.to_string(),
        policy,
        status,
        fatal: true,
        offset,
        len,
        expected_sha256: expected.map(RangeHash::hex),
        actual_sha256: Some(actual.hex()),
        detail: detail.to_string(),
        files: Vec::new(),
    }
}

/// Compare partition-by-partition two images that share a GPT layout.
pub fn compare_os(expected: &Path, actual: &Path) -> Result<ImageReport> {
    let mut images = Images::open(expected, actual)?;
    let expected_len = disk::file_len(&images.expected)?;
    let actual_len = disk::file_len(&images.actual)?;
    let mut report = ImageReport {
        expected: Some(expected.to_path_buf()),
        actual: Some(actual.to_path_buf()),
        expected_len,
        actual_len,
        regions: Vec::new(),
    };

    if actual_len < expected_len {
        report.regions.push(RegionReport {
            name: "SIZE".to_string(),
            policy: Policy::MustMatch,
            status: Status::Mismatch,
            fatal: true,
            offset: 0,
            len: expected_len,
            expected_sha256: None,
            actual_sha256: None,
            detail: format!(
                "published image ({actual_len} bytes) is smaller than the rebuilt image ({expected_len} bytes)"
            ),
            files: Vec::new(),
        });
        return Ok(report);
    }

    let layout = DiskLayout::read(&mut images.expected)?;
    let gpt_ranges = [
        (0, layout.primary_gpt_end),
        (
            layout.backup_gpt.0,
            layout.backup_gpt.1 - layout.backup_gpt.0,
        ),
    ];
    let (e, a) = images.hash(&gpt_ranges)?;
    let mut gpt = region("GPT", Policy::MustMatch, &gpt_ranges, Some(&e), &a);
    gpt.detail = match gpt.status {
        Status::Match => "protective MBR, primary and backup GPT identical".to_string(),
        _ => "partition tables differ; partition comparisons use the rebuilt layout".to_string(),
    };
    report.regions.push(gpt);

    let gaps = layout.unallocated(expected_len);
    if !gaps.is_empty() {
        let (e, a) = images.hash(&gaps)?;
        report.regions.push(region(
            "UNALLOCATED",
            Policy::MustMatch,
            &gaps,
            Some(&e),
            &a,
        ));
    }

    for p in &layout.partitions {
        let policy = p.policy();
        let ranges = [(p.offset, p.len)];
        let (e, a) = images.hash(&ranges)?;
        let r = region(&p.name, policy, &ranges, Some(&e), &a);
        report.regions.push(r);
    }

    if actual_len > expected_len {
        let tail = [(expected_len, actual_len - expected_len)];
        let a = disk::hash_ranges(&mut images.actual, &tail)?;
        let mut r = region("PADDING", Policy::MustBeZero, &tail, None, &a);
        if r.status == Status::Match {
            r.detail = "bytes beyond the rebuilt image are zero".to_string();
        }
        report.regions.push(r);
    }

    Ok(report)
}

/// Compare the data image over the rebuilt image's length, and check that the rest is zero.
pub fn compare_data(expected: &Path, actual: &Path) -> Result<ImageReport> {
    let mut images = Images::open(expected, actual)?;
    let expected_len = disk::file_len(&images.expected)?;
    let actual_len = disk::file_len(&images.actual)?;
    let mut report = ImageReport {
        expected: Some(expected.to_path_buf()),
        actual: Some(actual.to_path_buf()),
        expected_len,
        actual_len,
        regions: Vec::new(),
    };
    let common = [(0, expected_len.min(actual_len))];
    let (e, a) = images.hash(&common)?;
    let mut r = region("DATA", Policy::MustMatch, &common, Some(&e), &a);
    if actual_len < expected_len {
        r.status = Status::Mismatch;
        r.detail = format!(
            "published image ({actual_len} bytes) is smaller than the rebuilt image ({expected_len} bytes)"
        );
    }
    report.regions.push(r);
    if actual_len > expected_len {
        let tail = [(expected_len, actual_len - expected_len)];
        let a = disk::hash_ranges(&mut images.actual, &tail)?;
        report
            .regions
            .push(region("PADDING", Policy::MustBeZero, &tail, None, &a));
    }
    Ok(report)
}

/// Report a data image that exists on only one side, which fails verification.
fn missing_data(expected: Option<&Path>, actual: Option<&Path>) -> Result<ImageReport> {
    let Some(path) = expected.or(actual) else {
        snafu::whatever!("no data image given");
    };
    let detail = if expected.is_some() {
        "the rebuild produced a data image, but the AMI has no data volume"
    } else {
        "the AMI has a data volume, but the rebuild produced no data image"
    };
    let len = disk::file_len(
        &File::open(path).whatever_context(format!("failed to open {}", path.display()))?,
    )?;
    Ok(ImageReport {
        expected: expected.map(Path::to_path_buf),
        actual: actual.map(Path::to_path_buf),
        expected_len: if expected.is_some() { len } else { 0 },
        actual_len: if actual.is_some() { len } else { 0 },
        regions: vec![RegionReport {
            name: "DATA".to_string(),
            policy: Policy::MustMatch,
            status: Status::Mismatch,
            fatal: true,
            offset: 0,
            len,
            expected_sha256: None,
            actual_sha256: None,
            detail: detail.to_string(),
            files: Vec::new(),
        }],
    })
}

/// Compare the OS image and the data images. A data image given on only one
/// side fails verification.
pub fn compare(
    expected: &Path,
    actual: &Path,
    expected_data: Option<&Path>,
    actual_data: Option<&Path>,
) -> Result<Report> {
    let os = compare_os(expected, actual)?;
    let data = match (expected_data, actual_data) {
        (Some(e), Some(a)) => Some(compare_data(e, a)?),
        (None, None) => None,
        (e, a) => Some(missing_data(e, a)?),
    };
    let failed = os.failed() || data.as_ref().is_some_and(ImageReport::failed);
    Ok(Report {
        verdict: if failed {
            Verdict::Failed
        } else {
            Verdict::Verified
        },
        os,
        data,
        notes: NOTES.iter().map(|s| s.to_string()).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::tests::{write_gpt, MIB};
    use crate::disk::DATA_TYPE_GUID;
    use std::io::Write;
    use std::os::unix::fs::FileExt;

    fn image(dir: &Path, name: &str, len: u64) -> PathBuf {
        let path = dir.join(name);
        let mut f = File::create_new(&path).unwrap();
        write_gpt(
            &mut f,
            len,
            &[
                ("BOTTLEROCKET-ROOT-A", [1; 16], 1, 2),
                ("BOTTLEROCKET-PRIVATE", [2; 16], 3, 1),
                ("BOTTLEROCKET-ROOT-B", [1; 16], 4, 1),
                ("", DATA_TYPE_GUID, 5, 2),
            ],
        );
        f.write_all_at(b"rootfs", MIB).unwrap();
        f.write_all_at(b"private", 3 * MIB).unwrap();
        f.write_all_at(b"data", 5 * MIB).unwrap();
        f.flush().unwrap();
        path
    }

    fn status(report: &ImageReport, name: &str) -> Status {
        report
            .regions
            .iter()
            .find(|r| r.name == name)
            .unwrap()
            .status
    }

    #[test]
    fn identical_images_verify() {
        let dir = tempfile::tempdir().unwrap();
        let e = image(dir.path(), "e.img", 8 * MIB);
        let a = image(dir.path(), "a.img", 8 * MIB);
        // The published snapshot is padded to a whole volume size.
        File::options()
            .write(true)
            .open(&a)
            .unwrap()
            .set_len(16 * MIB)
            .unwrap();
        let report = compare(&e, &a, None, None).unwrap();
        assert_eq!(report.verdict, Verdict::Verified, "{report:#?}");
        assert_eq!(status(&report.os, "PADDING"), Status::Match);
        assert_eq!(status(&report.os, "ROOT-A"), Status::Match);
    }

    #[test]
    fn flipped_root_byte_fails() {
        let dir = tempfile::tempdir().unwrap();
        let e = image(dir.path(), "e.img", 8 * MIB);
        let a = image(dir.path(), "a.img", 8 * MIB);
        File::options()
            .write(true)
            .open(&a)
            .unwrap()
            .write_all_at(b"R", MIB)
            .unwrap();
        let report = compare(&e, &a, None, None).unwrap();
        assert_eq!(report.verdict, Verdict::Failed);
        assert_eq!(status(&report.os, "ROOT-A"), Status::Mismatch);
        assert_eq!(status(&report.os, "PRIVATE"), Status::Match);
    }

    #[test]
    fn nonzero_b_bank_fails() {
        let dir = tempfile::tempdir().unwrap();
        let e = image(dir.path(), "e.img", 8 * MIB);
        let a = image(dir.path(), "a.img", 8 * MIB);
        File::options()
            .write(true)
            .open(&a)
            .unwrap()
            .write_all_at(b"x", 4 * MIB)
            .unwrap();
        let report = compare(&e, &a, None, None).unwrap();
        assert_eq!(report.verdict, Verdict::Failed);
        assert_eq!(status(&report.os, "ROOT-B"), Status::Mismatch);
    }

    #[test]
    fn nonzero_padding_fails() {
        let dir = tempfile::tempdir().unwrap();
        let e = image(dir.path(), "e.img", 8 * MIB);
        let a = image(dir.path(), "a.img", 8 * MIB);
        let f = File::options().write(true).open(&a).unwrap();
        f.set_len(16 * MIB).unwrap();
        f.write_all_at(b"x", 12 * MIB).unwrap();
        let report = compare(&e, &a, None, None).unwrap();
        assert_eq!(report.verdict, Verdict::Failed);
        assert_eq!(status(&report.os, "PADDING"), Status::Mismatch);
    }

    #[test]
    fn truncated_image_fails() {
        let dir = tempfile::tempdir().unwrap();
        let e = image(dir.path(), "e.img", 8 * MIB);
        let a = dir.path().join("a.img");
        std::fs::write(&a, b"short").unwrap();
        let report = compare(&e, &a, None, None).unwrap();
        assert_eq!(report.verdict, Verdict::Failed);
        assert_eq!(status(&report.os, "SIZE"), Status::Mismatch);
    }

    #[test]
    fn data_image() {
        let dir = tempfile::tempdir().unwrap();
        let e = dir.path().join("e-data.img");
        let a = dir.path().join("a-data.img");
        std::fs::write(&e, b"data").unwrap();
        std::fs::write(&a, b"data\0\0\0\0").unwrap();
        let os_e = image(dir.path(), "e.img", 8 * MIB);
        let os_a = image(dir.path(), "a.img", 8 * MIB);
        let report = compare(&os_e, &os_a, Some(&e), Some(&a)).unwrap();
        assert_eq!(report.verdict, Verdict::Verified);

        std::fs::write(&a, b"dat4").unwrap();
        let report = compare(&os_e, &os_a, Some(&e), Some(&a)).unwrap();
        assert_eq!(report.verdict, Verdict::Failed);
        assert_eq!(
            status(report.data.as_ref().unwrap(), "DATA"),
            Status::Mismatch
        );
    }

    #[test]
    fn one_sided_data_image_fails() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data.img");
        std::fs::write(&data, b"data").unwrap();
        let os_e = image(dir.path(), "e.img", 8 * MIB);
        let os_a = image(dir.path(), "a.img", 8 * MIB);
        for (e, a) in [(Some(data.as_path()), None), (None, Some(data.as_path()))] {
            let report = compare(&os_e, &os_a, e, a).unwrap();
            assert_eq!(report.verdict, Verdict::Failed);
            assert_eq!(
                status(report.data.as_ref().unwrap(), "DATA"),
                Status::Mismatch
            );
        }
    }
}
