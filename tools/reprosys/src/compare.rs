//! Compare a rebuilt disk image against the image published in an AMI.

use crate::disk::{self, DiskLayout, Partition, Policy, RangeHash};
use crate::erofs::{self, ErofsTree};
use crate::error::Result;
use crate::fsfiles::{self, FileReport, FileStatus, Rules};
use crate::verity::VerityTable;
use serde::Serialize;
use sha2::{Digest, Sha256};
use snafu::{ensure_whatever, OptionExt, ResultExt};
use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Match,
    Mismatch,
    ExpectedDifference,
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

/// The GRUB configuration in BOOT-A, which holds the kernel command line.
const GRUB_CFG: &[u8] = b"/grub/grub.cfg";

const NOTES: &[&str] = &[];

struct Images {
    expected: File,
    actual: File,
    expected_path: PathBuf,
    actual_path: PathBuf,
}

impl Images {
    fn open(expected: &Path, actual: &Path) -> Result<Self> {
        let open =
            |p: &Path| File::open(p).whatever_context(format!("failed to open {}", p.display()));
        Ok(Self {
            expected: open(expected)?,
            actual: open(actual)?,
            expected_path: expected.to_path_buf(),
            actual_path: actual.to_path_buf(),
        })
    }

    fn hash(&mut self, ranges: &[(u64, u64)]) -> Result<(RangeHash, RangeHash)> {
        Ok((
            disk::hash_ranges(&mut self.expected, ranges)?,
            disk::hash_ranges(&mut self.actual, ranges)?,
        ))
    }

    fn read(&mut self, p: &Partition) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok((
            disk::read_range(&mut self.expected, p.offset, p.len)?,
            disk::read_range(&mut self.actual, p.offset, p.len)?,
        ))
    }
}

fn assess_region(
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
    let gpt_ranges = layout.gpt_ranges();
    let (e, a) = images.hash(&gpt_ranges)?;
    let mut gpt = assess_region("GPT", Policy::MustMatch, &gpt_ranges, Some(&e), &a);
    gpt.detail = match gpt.status {
        Status::Match => "protective MBR, primary and backup GPT identical".to_string(),
        _ => "partition tables differ; partition comparisons use the rebuilt layout".to_string(),
    };
    report.regions.push(gpt);

    let gaps = layout.unallocated(expected_len);
    if !gaps.is_empty() {
        let (e, a) = images.hash(&gaps)?;
        report.regions.push(assess_region(
            "UNALLOCATED",
            Policy::MustMatch,
            &gaps,
            Some(&e),
            &a,
        ));
    }

    let mut grub_cfgs = (None, None);
    for p in &layout.partitions {
        let policy = p.policy();
        let ranges = [(p.offset, p.len)];
        let (e, a) = images.hash(&ranges)?;
        let mut r = assess_region(&p.name, policy, &ranges, Some(&e), &a);
        match policy {
            Policy::MustMatch | Policy::MustBeZero | Policy::BootConfig => {}
            Policy::SaltDependent => {
                r.fatal = false;
                if r.status != Status::Match {
                    r.status = Status::ExpectedDifference;
                    r.detail = "differs; depends on the random verity salt and is not compared"
                        .to_string();
                }
            }
            Policy::FilesMustMatch if r.status != Status::Match => {
                compare_root(&images, p, &mut r)?
            }
            Policy::FilesMustMatch => {}
            Policy::SigningDependent => {
                // Boot bytes still have to match until signing exceptions are introduced.
                if p.name == "BOOT-A" {
                    let (exp, act) = images.read(p)?;
                    let exp = fsfiles::ext4_files(exp)?;
                    let act = fsfiles::ext4_files(act)?;
                    grub_cfgs = (exp.get(GRUB_CFG).cloned(), act.get(GRUB_CFG).cloned());
                }
            }
        }
        report.regions.push(r);
    }

    // The boot configuration check needs grub.cfg, so run it after BOOT-A was read.
    if layout.find("HASH-A").is_some() {
        let result = check_boot_config(grub_cfgs.0.as_deref(), grub_cfgs.1.as_deref());
        report.regions.push(boot_config_region(
            layout.find("BOOT-A"),
            &grub_cfgs,
            &result,
        ));
    }

    if actual_len > expected_len {
        let tail = [(expected_len, actual_len - expected_len)];
        let a = disk::hash_ranges(&mut images.actual, &tail)?;
        let mut r = assess_region("PADDING", Policy::MustBeZero, &tail, None, &a);
        if r.status == Status::Match {
            r.detail = "bytes beyond the rebuilt image are zero".to_string();
        }
        report.regions.push(r);
    }

    Ok(report)
}

/// Compare a ROOT-A whose bytes differ file by file. Only erofs is supported;
/// any other ROOT-A that differs fails.
fn compare_root(images: &Images, p: &Partition, r: &mut RegionReport) -> Result<()> {
    let fs_name = |erofs: bool| if erofs { "erofs" } else { "not erofs" };
    let expected_erofs = erofs::is_erofs(&images.expected, p.offset)?;
    let actual_erofs = erofs::is_erofs(&images.actual, p.offset)?;
    if !(expected_erofs && actual_erofs) {
        r.detail = format!(
            "the rebuilt ROOT-A is {} and the published ROOT-A is {}; only erofs root \
             filesystems are supported, so the files were not compared",
            fs_name(expected_erofs),
            fs_name(actual_erofs)
        );
        return Ok(());
    }
    erofs::require_tools()?;
    // Extract next to the published image, where there is room.
    let work_dir = images
        .actual_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let files = (|| {
        // Compressed files can expand to any size, so bound them before extracting.
        let expected_size = erofs::total_file_size(&images.expected_path, p.offset)?;
        let actual_size = erofs::total_file_size(&images.actual_path, p.offset)?;
        ensure_whatever!(
            actual_size <= expected_size.saturating_add(p.len),
            "the published ROOT-A holds {actual_size} bytes of files, more than the rebuilt \
             ROOT-A ({expected_size} bytes) plus the size of the partition; it was not \
             extracted"
        );
        let e = ErofsTree::extract(&images.expected_path, p.offset, p.len, work_dir)?;
        let a = ErofsTree::extract(&images.actual_path, p.offset, p.len, work_dir)?;
        fsfiles::compare_trees(&e, &a, Rules::Root, p.len)
    })();
    match files {
        Ok(files) => {
            let mismatches = files
                .iter()
                .filter(|f| f.status == FileStatus::Mismatch)
                .count();
            if files.is_empty() {
                r.detail = "contents differ, but all entries are identical; the difference is in \
                            what is not compared (timestamps or filesystem layout)"
                    .to_string();
            } else if mismatches == 0 {
                r.status = Status::ExpectedDifference;
                r.detail = format!(
                    "files differ only in kernel module signatures, the TUF root role and the SBOMs; {} differing files listed",
                    files.len()
                );
            } else {
                r.detail = format!(
                    "{mismatches} of {} differing files differ beyond kernel module signatures, the TUF root role and the SBOMs",
                    files.len()
                );
            }
            r.files = files;
        }
        Err(e) => {
            r.detail = format!("contents differ and files could not be read: {e}");
        }
    }
    Ok(())
}

/// Check that the published boot configuration matches the rebuilt one except
/// for the verity root hash and salt, with a single verity table for the same
/// devices, and return the published table.
fn check_boot_config(expected: Option<&[u8]>, actual: Option<&[u8]>) -> Result<VerityTable> {
    let expected =
        expected.whatever_context("no /grub/grub.cfg could be read from the rebuilt BOOT-A")?;
    let actual =
        actual.whatever_context("no /grub/grub.cfg could be read from the published BOOT-A")?;
    let same_beyond_verity =
        fsfiles::normalize_verity(expected) == fsfiles::normalize_verity(actual);
    ensure_whatever!(
        same_beyond_verity,
        "the published grub.cfg differs from the rebuilt grub.cfg beyond the verity root hash and salt"
    );
    let table = |grub_cfg: &[u8], side: &str| -> Result<VerityTable> {
        // The whole file must hold a single table, not just the parsed command line.
        VerityTable::find_unique(grub_cfg)
            .with_whatever_context(|_| format!("invalid {side} grub.cfg"))?;
        let cmdline = pcrsys::parsers::grub::parse(grub_cfg)
            .whatever_context(format!("failed to parse the {side} grub.cfg"))?;
        VerityTable::find_unique(cmdline.as_bytes())
            .with_whatever_context(|_| format!("invalid {side} kernel command line"))
    };
    let rebuilt = table(expected, "rebuilt")?;
    let published = table(actual, "published")?;
    ensure_whatever!(
        VerityTable {
            root_hash: rebuilt.root_hash.clone(),
            salt: rebuilt.salt.clone(),
            ..published.clone()
        } == rebuilt,
        "the published verity table differs from the rebuilt one beyond the root hash and salt"
    );
    Ok(published)
}

fn boot_config_region(
    boot: Option<&Partition>,
    (expected, actual): &(Option<Vec<u8>>, Option<Vec<u8>>),
    result: &Result<VerityTable>,
) -> RegionReport {
    let sha256 = |f: &Option<Vec<u8>>| f.as_ref().map(|f| hex::encode(Sha256::digest(f)));
    let (status, detail) = match result {
        Ok(_) if expected == actual => (Status::Match, "grub.cfg identical".to_string()),
        Ok(table) => (
            Status::ExpectedDifference,
            format!(
                "grub.cfg differs only in the verity root hash and salt; the published image boots \
                 ROOT-A ({}) and HASH-A ({}) with root hash {}",
                table.data_device,
                table.hash_device,
                hex::encode(&table.root_hash)
            ),
        ),
        Err(e) => (Status::Mismatch, e.to_string()),
    };
    RegionReport {
        name: "BOOT-CONFIG".to_string(),
        policy: Policy::BootConfig,
        status,
        fatal: true,
        offset: boot.map_or(0, |p| p.offset),
        len: boot.map_or(0, |p| p.len),
        expected_sha256: sha256(expected),
        actual_sha256: sha256(actual),
        detail,
        files: Vec::new(),
    }
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
    let mut r = assess_region("DATA", Policy::MustMatch, &common, Some(&e), &a);
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
        report.regions.push(assess_region(
            "PADDING",
            Policy::MustBeZero,
            &tail,
            None,
            &a,
        ));
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

/// Compare the OS image and the data images.
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

    pub(super) fn grub_cfg(root: &str, salt: &str, extra: &str) -> Vec<u8> {
        format!(
            "set default=\"0\"\n\
             set dm_verity_root=\"root,,,ro,0 2400 verity 1 PARTUUID=$boot_uuid/PARTNROFF=1 \
             PARTUUID=$boot_uuid/PARTNROFF=2 4096 4096 300 1 sha256 {root} {salt} 2 \
             restart_on_corruption ignore_zero_blocks\"\n\
             menuentry \"Bottlerocket OS\" {{\n\
             \x20  linux ($root)/vmlinuz root=/dev/dm-0 ro{extra} dm-mod.create=\"$dm_verity_root\" -- \
             systemd.log_target=journal\n\
             \x20  initrd ($private)/bootconfig.data\n\
             }}\n"
        )
        .into_bytes()
    }

    #[test]
    fn boot_config_may_differ_only_in_verity_digests() {
        let (root, other_root) = ("a".repeat(64), "b".repeat(64));
        let rebuilt = grub_cfg(&root, "00", "");
        let published = grub_cfg(&other_root, "11", "");
        let table = check_boot_config(Some(&rebuilt), Some(&published)).unwrap();
        assert_eq!(hex::encode(&table.root_hash), other_root);
        assert_eq!(table.salt, [0x11]);
        assert_eq!(table.data_device, "PARTUUID=/PARTNROFF=1");

        let report = |p: &[u8]| {
            let cfgs = (Some(rebuilt.clone()), Some(p.to_vec()));
            boot_config_region(None, &cfgs, &check_boot_config(cfgs.0.as_deref(), Some(p)))
        };
        let region = report(&published);
        assert_eq!(region.status, Status::ExpectedDifference);
        assert!(!region.failed());

        // Another command line, a decoy table, or no grub.cfg fail verification.
        for bad in [
            grub_cfg(&other_root, "11", " init=/bin/sh"),
            [
                grub_cfg(&other_root, "11", ""),
                format!("# verity 1 a b 4096 4096 300 1 sha256 {root} 00\n").into_bytes(),
            ]
            .concat(),
        ] {
            let region = report(&bad);
            assert_eq!(region.status, Status::Mismatch, "{region:#?}");
            assert!(region.failed());
        }
        assert!(check_boot_config(Some(&rebuilt), None).is_err());
        assert!(check_boot_config(None, Some(&published)).is_err());

        // A second table is rejected even when the rebuilt grub.cfg has one too.
        let twice = |r: &str, s: &str| [grub_cfg(r, s, ""), grub_cfg(r, s, "")].concat();
        assert!(
            check_boot_config(Some(&twice(&root, "00")), Some(&twice(&other_root, "11"))).is_err()
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

/// Comparisons of real filesystems, which need `mkfs.ext4` and erofs-utils.
#[cfg(test)]
mod rootfs_tests {
    use super::*;
    use crate::disk::tests::{write_gpt, MIB};
    use crate::fsfiles::FileTree;
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileExt, PermissionsExt};
    use std::process::Command;

    struct Rootfs<'a> {
        signing_key: &'a [u8],
        os_release: &'a str,
        all_root: bool,
        /// Value of `user.big` on /etc/os-release, long enough to be shown by digest.
        big_xattr: &'a [u8],
        /// The device number of a character device at /console: 1:3 or 1:5.
        console: Option<(u32, u32)>,
    }

    const BIG_XATTR: &[u8] = &[b'x'; 600];

    const DEFAULT: Rootfs<'static> = Rootfs {
        signing_key: b"key-one",
        os_release: "v1",
        all_root: true,
        big_xattr: BIG_XATTR,
        console: None,
    };

    fn set_xattr(path: &Path, name: &str, value: &[u8]) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let name = CString::new(name).unwrap();
        // SAFETY: the pointers are valid for the duration of the call.
        let rc = unsafe {
            libc::lsetxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    }

    fn populate(src: &Path, rootfs: &Rootfs) {
        let modules = src.join("lib/modules/6.1/kernel");
        std::fs::create_dir_all(&modules).unwrap();
        std::fs::create_dir_all(src.join("etc")).unwrap();
        std::fs::write(
            modules.join("xfs.ko"),
            crate::kmod::tests::sign(b"\x7fELFxfs", rootfs.signing_key),
        )
        .unwrap();
        std::fs::write(src.join("etc/os-release"), rootfs.os_release).unwrap();
        std::fs::write(src.join("etc/shadow"), "root:*").unwrap();
        std::fs::write(src.join("etc/sudo"), "suid").unwrap();
        std::os::unix::fs::symlink("../lib", src.join("etc/lib")).unwrap();
        // On enough entries that erofs stores it once, as a shared xattr.
        for p in ["etc/shadow", "etc/sudo", "etc/os-release", "lib"] {
            set_xattr(&src.join(p), "user.small", b"1");
        }
        set_xattr(&src.join("etc/os-release"), "user.big", rootfs.big_xattr);
        let chmod =
            |p: &str, mode| std::fs::set_permissions(src.join(p), PermissionsExt::from_mode(mode));
        chmod("etc/shadow", 0o400).unwrap();
        chmod("etc/sudo", 0o4755).unwrap();
        chmod("lib/modules", 0o555).unwrap();
    }

    fn mkfs(dir: &Path, name: &str, rootfs: &Rootfs) -> Vec<u8> {
        let src = dir.join(format!("{name}-src"));
        populate(&src, rootfs);
        let img = dir.join(format!("{name}.fs"));
        let mut cmd = Command::new("mkfs.erofs");
        cmd.args(["-T", "1", "-U", "11111111-1111-1111-1111-111111111111"]);
        cmd.args(["-z", "lz4hc,12"]);
        if rootfs.all_root {
            cmd.arg("--all-root");
        }
        if let Some(console) = rootfs.console {
            // Creating device nodes needs root, so archive existing ones under a new name.
            let dev = match console {
                (1, 3) => "dev/null",
                (1, 5) => "dev/zero",
                _ => unreachable!("no device node for {console:?}"),
            };
            let tar = dir.join(format!("{name}.tar"));
            let output = Command::new("tar")
                .args(["--format=posix", "--xattrs", "--xattrs-include=user.*"])
                .arg(format!("--transform=s,^{dev}$,./console,"))
                .arg("-cf")
                .arg(&tar)
                .arg("-C")
                .arg(&src)
                .arg(".")
                .args(["-C", "/", dev])
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            cmd.arg("--tar=f").arg(&img).arg(tar);
        } else {
            cmd.arg(&img).arg(&src);
        }
        let output = cmd.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        std::fs::set_permissions(src.join("lib/modules"), PermissionsExt::from_mode(0o755))
            .unwrap();
        std::fs::read(img).unwrap()
    }

    /// A disk image whose ROOT-A holds `root`.
    fn root_image(dir: &Path, name: &str, root: &[u8]) -> PathBuf {
        let path = dir.join(format!("{name}.img"));
        let mut f = File::create_new(&path).unwrap();
        write_gpt(&mut f, 8 * MIB, &[("BOTTLEROCKET-ROOT-A", [1; 16], 1, 2)]);
        f.write_all_at(root, MIB).unwrap();
        path
    }

    fn os_image(dir: &Path, name: &str, rootfs: &Rootfs) -> PathBuf {
        root_image(dir, name, &mkfs(dir, name, rootfs))
    }

    fn entries(image: &Path) -> BTreeMap<Vec<u8>, fsfiles::Entry> {
        let tree = ErofsTree::extract(image, MIB, 2 * MIB, image.parent().unwrap()).unwrap();
        let entries = tree.entries().unwrap().into_iter();
        entries.map(|(path, (_, e))| (path, e)).collect()
    }

    fn root_a(expected: &Path, actual: &Path) -> RegionReport {
        let report = compare(expected, actual, None, None).unwrap();
        let root = report.os.regions.into_iter().find(|r| r.name == "ROOT-A");
        root.unwrap()
    }

    fn file<'a>(r: &'a RegionReport, path: &str) -> &'a FileReport {
        r.files.iter().find(|f| f.path == path).unwrap()
    }

    #[test]
    #[ignore = "needs erofs-utils"]
    fn erofs_root() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let rebuilt = os_image(d, "rebuilt", &DEFAULT);

        let found = entries(&rebuilt);
        assert!(found.contains_key(b"/".as_slice()), "{found:?}");
        let user = |path: &str, name: &str| {
            found[&path.as_bytes().to_vec()]
                .xattrs
                .get(name.as_bytes())
                .cloned()
        };
        assert_eq!(user("/etc/sudo", "user.small"), Some(b"1".to_vec()));
        assert_eq!(user("/lib", "user.small"), Some(b"1".to_vec()));
        assert_eq!(
            user("/etc/os-release", "user.big"),
            Some(BIG_XATTR.to_vec())
        );
        assert_eq!(user("/etc/lib", "user.small"), None);

        let same = os_image(d, "same", &DEFAULT);
        assert_eq!(root_a(&rebuilt, &same).status, Status::Match);

        let resigned = Rootfs {
            signing_key: b"key-two",
            ..DEFAULT
        };
        let r = root_a(&rebuilt, &os_image(d, "resigned", &resigned));
        assert_eq!(r.status, Status::ExpectedDifference, "{r:#?}");
        assert_eq!(r.files.len(), 1, "{r:#?}");
        assert_eq!(
            file(&r, "/lib/modules/6.1/kernel/xfs.ko").status,
            FileStatus::ExpectedDifference
        );

        let changed = Rootfs {
            signing_key: b"key-two",
            os_release: "v2",
            ..DEFAULT
        };
        let r = root_a(&rebuilt, &os_image(d, "changed", &changed));
        assert_eq!(r.status, Status::Mismatch, "{r:#?}");
        assert_eq!(file(&r, "/etc/os-release").status, FileStatus::Mismatch);

        // A changed xattr fails, even alongside an expected difference.
        let mut big = BIG_XATTR.to_vec();
        *big.last_mut().unwrap() = b'y';
        let relabeled = Rootfs {
            signing_key: b"key-two",
            big_xattr: &big,
            ..DEFAULT
        };
        let r = root_a(&rebuilt, &os_image(d, "relabeled", &relabeled));
        assert_eq!(r.status, Status::Mismatch, "{r:#?}");
        let detail = &file(&r, "/etc/os-release").detail;
        assert!(
            detail.starts_with("xattr user.big 600 bytes, sha256 "),
            "{detail}"
        );

        let owned = Rootfs {
            all_root: false,
            ..DEFAULT
        };
        let r = root_a(&rebuilt, &os_image(d, "owned", &owned));
        assert_eq!(r.status, Status::Mismatch, "{r:#?}");
        assert!(
            file(&r, "/etc/shadow").detail.starts_with("owner 0:0 vs"),
            "{r:#?}"
        );
        // Device nodes are compared, though extraction skips them.
        let null = Rootfs {
            console: Some((1, 3)),
            ..DEFAULT
        };
        let with_null = os_image(d, "null", &null);
        let console = &entries(&with_null)[b"/console".as_slice()];
        assert_eq!(console.kind, fsfiles::Kind::CharDevice);
        assert_eq!(console.device, Some((1, 3)));
        let r = root_a(
            &with_null,
            &os_image(
                d,
                "null-resigned",
                &Rootfs {
                    signing_key: b"key-two",
                    ..null
                },
            ),
        );
        assert_eq!(r.status, Status::ExpectedDifference, "{r:#?}");
        let zero = Rootfs {
            signing_key: b"key-two",
            console: Some((1, 5)),
            ..DEFAULT
        };
        let r = root_a(&with_null, &os_image(d, "zero", &zero));
        assert_eq!(r.status, Status::Mismatch, "{r:#?}");
        assert_eq!(file(&r, "/console").detail, "device 1:3 vs 1:5");
        let r = root_a(&with_null, &os_image(d, "no-console", &resigned));
        assert_eq!(r.status, Status::Mismatch, "{r:#?}");
        assert_eq!(file(&r, "/console").detail, "missing from published image");

        // Extraction directories are cleaned up, even read-only ones.
        let leftovers: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("erofs-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// An ext4 filesystem of `size` holding `files` and hardlinks to them.
    fn boot_fs(
        dir: &Path,
        name: &str,
        size: &str,
        files: &[(&str, &[u8])],
        links: &[(&str, &str)],
    ) -> Vec<u8> {
        let src = dir.join(format!("{name}-src"));
        for (path, contents) in files {
            let path = src.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        for (target, link) in links {
            std::fs::hard_link(src.join(target), src.join(link)).unwrap();
        }
        let img = dir.join(format!("{name}.fs"));
        let output = Command::new("mkfs.ext4")
            .env("E2FSPROGS_FAKE_TIME", "1")
            .args([
                "-q",
                "-b",
                "1024",
                "-U",
                "11111111-1111-1111-1111-111111111111",
            ])
            .args([
                "-E",
                "hash_seed=22222222-2222-2222-2222-222222222222,root_owner=0:0",
                "-d",
            ])
            .arg(&src)
            .arg(&img)
            .arg(size)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        std::fs::read(img).unwrap()
    }

    #[test]
    #[ignore = "needs mkfs.ext4"]
    fn hash_a_may_differ_by_salt() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let root = vec![7u8; 300 * 4096];

        let image = |name: &str, root_hash: &str, salt: &str, hash: &[u8]| {
            let boot = boot_fs(
                d,
                name,
                "1M",
                &[(
                    "grub/grub.cfg",
                    &super::tests::grub_cfg(root_hash, salt, ""),
                )],
                &[],
            );
            let path = d.join(format!("{name}.img"));
            let mut f = File::create_new(&path).unwrap();
            write_gpt(
                &mut f,
                8 * MIB,
                &[
                    ("BOTTLEROCKET-BOOT-A", [1; 16], 1, 1),
                    ("BOTTLEROCKET-ROOT-A", [1; 16], 2, 2),
                    ("BOTTLEROCKET-HASH-A", [1; 16], 4, 1),
                ],
            );
            f.write_all_at(&boot, MIB).unwrap();
            f.write_all_at(&root, 2 * MIB).unwrap();
            f.write_all_at(hash, 4 * MIB).unwrap();
            path
        };
        let rebuilt = image("rebuilt", &"a".repeat(64), "00", b"rebuilt hash tree");
        let region = |report: &Report, name: &str| {
            report
                .os
                .regions
                .iter()
                .find(|r| r.name == name)
                .unwrap()
                .clone()
        };

        let same = image("same", &"a".repeat(64), "00", b"rebuilt hash tree");
        let report = compare(&rebuilt, &same, None, None).unwrap();
        assert_eq!(report.verdict, Verdict::Verified, "{report:#?}");
        assert_eq!(region(&report, "HASH-A").status, Status::Match);
        assert_eq!(region(&report, "BOOT-CONFIG").status, Status::Match);

        // Another salt changes both grub.cfg and HASH-A; neither fails verification.
        let salted = image("salted", &"b".repeat(64), "11", b"other hash tree");
        let report = compare(&rebuilt, &salted, None, None).unwrap();
        let hash_a = region(&report, "HASH-A");
        assert_eq!(hash_a.status, Status::ExpectedDifference, "{hash_a:#?}");
        assert!(!hash_a.failed());
        let boot_config = region(&report, "BOOT-CONFIG");
        assert_eq!(boot_config.status, Status::ExpectedDifference);
        assert!(!boot_config.failed());
    }

    #[test]
    #[ignore = "needs mkfs.ext4"]
    fn boot_files_are_read_within_the_partition_size() {
        let dir = tempfile::tempdir().unwrap();
        let big = vec![7u8; 512 << 10];
        let links: Vec<_> = (0..8).map(|i| ("big", format!("link{i}"))).collect();
        let links: Vec<_> = links.iter().map(|(t, l)| (*t, l.as_str())).collect();
        let fs = boot_fs(dir.path(), "linked", "2M", &[("big", &big)], &links);
        let err = fsfiles::ext4_files(fs).unwrap_err().to_string();
        assert!(err.contains("more file data than the"), "{err}");

        let fs = boot_fs(dir.path(), "unlinked", "2M", &[("big", &big)], &[]);
        assert_eq!(fsfiles::ext4_files(fs).unwrap().len(), 1);
    }
}
