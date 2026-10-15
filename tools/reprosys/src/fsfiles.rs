//! File-level comparison of partitions whose bytes are expected to differ: the
//! signing-dependent boot partitions (EFI-A, BOOT-A) and ROOT-A, whose kernel
//! modules are signed with a per-build key.

use crate::error::Result;
use crate::kmod;
use ext4_view::Ext4;
use fatfs::{FileSystem, FsOptions};
use regex::bytes::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};
use snafu::{ensure_whatever, ResultExt};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{Cursor, Read};
use std::sync::LazyLock;

/// Files whose contents are produced by signing and are expected to differ.
const SIGNING_ARTIFACT_SUFFIXES: &[&str] =
    &[".sig", ".hmac", ".crt", ".cer", ".der", ".auth", ".esl"];

/// The TUF root role updog trusts. Rebuilds generate their own, since the
/// release root role's keys are not available outside the release process.
const TUF_ROOT_ROLE: &[u8] = b"/usr/share/updog/root.json";

/// PE sections that only hold embedded keys: shim's vendor certificate and
/// GRUB's public key for verifying grub.cfg.
const KEY_SECTIONS: &[&str] = &[".vendor_cert", ".pubkey"];

/// Largest file read into memory to compare it with a content-aware rule
/// (kernel modules and the TUF root role). Other files are hashed as they are read.
const MAX_BUFFERED_SIZE: u64 = 256 << 20;

/// Which differences are expected in a filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rules {
    /// EFI-A and BOOT-A: signatures, signing certificates, PE binaries that differ
    /// only in embedded keys, and the verity root hash and salt in grub.cfg.
    Boot,
    /// ROOT-A: the signatures appended to kernel modules, and the TUF root role.
    Root,
}

/// The verity root hash and salt in a device-mapper table.
static VERITY_DIGESTS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(sha256) [0-9a-fA-F]{64} (?:[0-9a-fA-F]+|-)").expect("valid regex")
});

/// An absolute path within a filesystem. File names are bytes and need not be UTF-8.
pub type FsPath = Vec<u8>;

pub type Files = BTreeMap<FsPath, Vec<u8>>;

/// Extended attributes, by full name (such as `security.selinux`).
pub type Xattrs = BTreeMap<Vec<u8>, Vec<u8>>;

/// Show a path or name in reports; invalid UTF-8 is replaced.
pub fn display(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Add `value` at `key`, failing if the key is already present, so that no
/// entry silently replaces another.
pub fn insert_unique<V>(map: &mut BTreeMap<Vec<u8>, V>, key: Vec<u8>, value: V) -> Result<()> {
    ensure_whatever!(!map.contains_key(&key), "duplicate entry {}", display(&key));
    map.insert(key, value);
    Ok(())
}

/// Bounds the bytes of files read from a partition. A filesystem without
/// hardlinks, sparse files or cross-linked clusters holds no more file data
/// than its size, so a published partition that claims more is rejected
/// before it can exhaust memory.
struct ReadBudget {
    limit: u64,
    remaining: u64,
}

impl ReadBudget {
    fn new(partition: &[u8]) -> Self {
        let limit = partition.len() as u64;
        Self {
            limit,
            remaining: limit,
        }
    }

    /// Account for reading `len` bytes of `path`.
    fn take(&mut self, path: &str, len: u64) -> Result<()> {
        ensure_whatever!(
            len <= self.remaining,
            "reading {path} ({len} bytes) would read more file data than the {}-byte partition holds",
            self.limit
        );
        self.remaining -= len;
        Ok(())
    }
}

/// Read every regular file from a FAT filesystem image.
pub fn fat_files(partition: Vec<u8>) -> Result<Files> {
    let mut budget = ReadBudget::new(&partition);
    let fs = FileSystem::new(Cursor::new(partition), FsOptions::new())
        .whatever_context("failed to mount FAT filesystem")?;
    let mut files = Files::new();
    let mut stack = vec![(String::new(), fs.root_dir())];
    while let Some((prefix, dir)) = stack.pop() {
        for entry in dir.iter() {
            let entry = entry.whatever_context("failed to read FAT directory")?;
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let path = format!("{prefix}/{name}");
            if entry.is_dir() {
                stack.push((path, entry.to_dir()));
            } else {
                budget.take(&path, entry.len())?;
                let mut contents = Vec::new();
                entry
                    .to_file()
                    .take(entry.len())
                    .read_to_end(&mut contents)
                    .whatever_context(format!("failed to read {path}"))?;
                insert_unique(&mut files, path.into_bytes(), contents)?;
            }
        }
    }
    Ok(files)
}

/// Read every regular file from an ext4 filesystem image.
pub fn ext4_files(partition: Vec<u8>) -> Result<Files> {
    let mut budget = ReadBudget::new(&partition);
    let fs = Ext4::load(Box::new(partition)).whatever_context("failed to mount ext4 filesystem")?;
    let mut files = Files::new();
    let mut stack = vec![ext4_view::PathBuf::new("/")];
    while let Some(dir) = stack.pop() {
        let entries = fs
            .read_dir(&dir)
            .whatever_context(format!("failed to read directory {}", dir.display()))?;
        for entry in entries {
            let entry =
                entry.whatever_context(format!("failed to read directory {}", dir.display()))?;
            let name = entry.file_name();
            let name = name.as_ref();
            if name == b"." || name == b".." || name == b"lost+found" {
                continue;
            }
            let path = entry.path();
            let metadata = entry
                .metadata()
                .whatever_context(format!("failed to stat {}", path.display()))?;
            if metadata.is_dir() {
                stack.push(path);
            } else if metadata.file_type().is_regular_file() {
                // A sparse file can claim any size, and hardlinks repeat one
                // file's data, so bound the total before reading.
                budget.take(&path.display().to_string(), metadata.len())?;
                let contents = fs
                    .read(&path)
                    .whatever_context(format!("failed to read {}", path.display()))?;
                insert_unique(&mut files, path.as_ref().to_vec(), contents)?;
            }
        }
    }
    Ok(files)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileStatus {
    Match,
    ExpectedDifference,
    Mismatch,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub path: String,
    pub status: FileStatus,
    pub detail: String,
}

fn is_pe(data: &[u8]) -> bool {
    data.starts_with(b"MZ")
}

/// Replace the verity root hash and salt in `data` with placeholders.
pub fn normalize_verity(data: &[u8]) -> Vec<u8> {
    VERITY_DIGESTS_RE
        .replace_all(data, &b"$1 <root-hash> <salt>"[..])
        .into_owned()
}

fn describe_contents(data: &[u8]) -> String {
    format!(
        "{} bytes, sha256 {}",
        data.len(),
        hex::encode(Sha256::digest(data))
    )
}

/// Compare a PE binary from a signing-dependent partition. Only differences
/// confined to sections holding embedded keys are expected; any other
/// difference is reported as a mismatch, with the sections that differ, even
/// though it may still come from per-build keys embedded in code or data
/// (the GRUB public key, or the kernel's module signing certificate).
fn compare_pe(expected: &[u8], actual: &[u8]) -> (FileStatus, String) {
    let (e, a) = match (
        pcrsys::pe::get_authenticode_hash(expected),
        pcrsys::pe::get_authenticode_hash(actual),
    ) {
        (Ok(e), Ok(a)) if e == a => {
            return (
                FileStatus::ExpectedDifference,
                "signatures differ; Authenticode digests match".to_string(),
            )
        }
        (Ok(e), Ok(a)) => (hex::encode(e), hex::encode(a)),
        _ => {
            return (
                FileStatus::Mismatch,
                "failed to compute Authenticode digest".to_string(),
            )
        }
    };
    let (status, detail) = describe_pe_difference(differing_sections(expected, actual));
    (
        status,
        format!("Authenticode digests differ ({e} vs {a}); {detail}"),
    )
}

/// Classify a difference between PE files with different Authenticode
/// digests, given the names of the sections whose contents differ.
fn describe_pe_difference(sections: Result<Vec<String>>) -> (FileStatus, String) {
    match sections {
        Ok(sections)
            if !sections.is_empty()
                && sections.iter().all(|s| KEY_SECTIONS.contains(&s.as_str())) =>
        {
            (
                FileStatus::ExpectedDifference,
                format!(
                    "differs only in sections holding embedded keys ({})",
                    sections.join(", ")
                ),
            )
        }
        Ok(sections) if sections.is_empty() => (
            FileStatus::Mismatch,
            "no section differs, so the headers do".to_string(),
        ),
        Ok(sections) => (
            FileStatus::Mismatch,
            format!(
                "differs in sections {}; this may still be caused by per-build keys embedded in \
                 code or data, such as the GRUB public key or the kernel module signing certificate",
                sections.join(", ")
            ),
        ),
        Err(e) => (
            FileStatus::Mismatch,
            format!("sections could not be compared: {e}"),
        ),
    }
}

/// Names of the PE sections that differ between two binaries, including
/// sections present in only one of them.
fn differing_sections(expected: &[u8], actual: &[u8]) -> Result<Vec<String>> {
    let expected: BTreeMap<_, _> = pcrsys::pe::sections(expected)
        .whatever_context("failed to read rebuilt PE sections")?
        .into_iter()
        .collect();
    let actual: BTreeMap<_, _> = pcrsys::pe::sections(actual)
        .whatever_context("failed to read published PE sections")?
        .into_iter()
        .collect();
    let mut names: Vec<_> = expected.keys().chain(actual.keys()).cloned().collect();
    names.sort();
    names.dedup();
    names.retain(|n| expected.get(n) != actual.get(n));
    Ok(names)
}

/// Compare a kernel module, ignoring its appended signature.
fn compare_module(path: &[u8], expected: &[u8], actual: &[u8]) -> (FileStatus, String) {
    let unsigned = |data: &[u8]| -> Result<Option<Vec<u8>>> {
        let module = kmod::decompress(path, data)?;
        Ok(kmod::split_signature(&module)?.map(|(body, _)| body.to_vec()))
    };
    match (unsigned(expected), unsigned(actual)) {
        (Ok(Some(e)), Ok(Some(a))) if e == a => (
            FileStatus::ExpectedDifference,
            "differs only in the appended module signature".to_string(),
        ),
        (Ok(Some(e)), Ok(Some(a))) => (
            FileStatus::Mismatch,
            format!(
                "module differs beyond its signature (unsigned: {} vs {})",
                describe_contents(&e),
                describe_contents(&a)
            ),
        ),
        (Ok(None), Ok(None)) => (
            FileStatus::Mismatch,
            format!(
                "unsigned module contents differ ({} vs {})",
                describe_contents(expected),
                describe_contents(actual)
            ),
        ),
        (Ok(e), Ok(a)) => {
            let side = |m: &Option<Vec<u8>>| if m.is_some() { "signed" } else { "unsigned" };
            (
                FileStatus::Mismatch,
                format!(
                    "module is {} in the rebuilt image but {} in the published image",
                    side(&e),
                    side(&a)
                ),
            )
        }
        (Err(e), _) | (_, Err(e)) => (FileStatus::Mismatch, format!("failed to read module: {e}")),
    }
}

/// Describe the published TUF root role, which is expected to differ from the
/// one generated by the rebuild. It cannot be verified against the source, so
/// identify it well enough to check against the repository's published root role.
fn describe_root_role(actual: &[u8]) -> (FileStatus, String) {
    let summary = serde_json::from_slice::<serde_json::Value>(actual)
        .ok()
        .and_then(|root| {
            let signed = root.get("signed")?;
            if signed.get("_type")?.as_str()? != "root" {
                return None;
            }
            let keys: Vec<&str> = signed
                .get("keys")?
                .as_object()?
                .keys()
                .map(String::as_str)
                .collect();
            Some(format!(
                "version {}, expires {}, keys {}",
                signed.get("version")?,
                signed.get("expires")?.as_str()?,
                keys.join(", ")
            ))
        });
    match summary {
        Some(summary) => (
            FileStatus::ExpectedDifference,
            format!(
                "TUF root role; rebuilds generate their own because the release root role keys \
                 are not available. Check the published root role against the one your \
                 repository publishes: sha512 {}, {summary}",
                hex::encode(Sha512::digest(actual))
            ),
        ),
        None => (
            FileStatus::Mismatch,
            format!(
                "published file is not a TUF root role ({})",
                describe_contents(actual)
            ),
        ),
    }
}

fn report(path: &[u8], status: FileStatus, detail: impl Into<String>) -> FileReport {
    FileReport {
        path: display(path),
        status,
        detail: detail.into(),
    }
}

/// Compare one file between the rebuilt and the published image.
fn compare_file(
    path: &[u8],
    expected: Option<&[u8]>,
    actual: Option<&[u8]>,
    rules: Rules,
) -> FileReport {
    let signing_artifact = rules == Rules::Boot
        && SIGNING_ARTIFACT_SUFFIXES
            .iter()
            .any(|s| path.to_ascii_lowercase().ends_with(s.as_bytes()));

    let (expected, actual) = match (expected, actual) {
        (Some(e), Some(a)) => (e, a),
        (None, _) | (_, None) if signing_artifact => {
            let side = if expected.is_none() {
                "rebuilt"
            } else {
                "published"
            };
            return report(
                path,
                FileStatus::ExpectedDifference,
                format!("signing artifact missing from {side} image"),
            );
        }
        (None, _) => return report(path, FileStatus::Mismatch, "missing from rebuilt image"),
        (_, None) => return report(path, FileStatus::Mismatch, "missing from published image"),
    };

    if expected == actual {
        return report(path, FileStatus::Match, "identical");
    }
    match rules {
        Rules::Boot => {
            if signing_artifact {
                return report(path, FileStatus::ExpectedDifference, "signing artifact");
            }
            if is_pe(expected) && is_pe(actual) {
                let (status, detail) = compare_pe(expected, actual);
                return report(path, status, detail);
            }
            if normalize_verity(expected) == normalize_verity(actual) {
                return report(
                    path,
                    FileStatus::ExpectedDifference,
                    "differs only in the verity root hash and salt",
                );
            }
        }
        Rules::Root => {
            if kmod::is_module(path) {
                let (status, detail) = compare_module(path, expected, actual);
                return report(path, status, detail);
            }
            if path.ends_with(TUF_ROOT_ROLE) {
                let (status, detail) = describe_root_role(actual);
                return report(path, status, detail);
            }
        }
    }
    report(
        path,
        FileStatus::Mismatch,
        format!(
            "contents differ ({} vs {})",
            describe_contents(expected),
            describe_contents(actual)
        ),
    )
}

/// Compare all files between two filesystems. Identical files are omitted
/// from the result, but every file compared is logged.
pub fn compare_files(expected: &Files, actual: &Files, rules: Rules) -> Vec<FileReport> {
    let mut paths: Vec<&FsPath> = expected.keys().chain(actual.keys()).collect();
    paths.sort();
    paths.dedup();
    paths
        .into_iter()
        .map(|p| {
            let (e, a) = (
                expected.get(p).map(Vec::as_slice),
                actual.get(p).map(Vec::as_slice),
            );
            let report = compare_file(p, e, a, rules);
            report
        })
        .filter(|r| r.status != FileStatus::Match)
        .collect()
}

/// The type of a filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Directory => "directory",
            Kind::Symlink => "symlink",
            Kind::CharDevice => "character device",
            Kind::BlockDevice => "block device",
            Kind::Fifo => "fifo",
            Kind::Socket => "socket",
        }
    }
}

/// The attributes of a filesystem entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: Kind,
    /// Permission bits, including setuid, setgid and sticky.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub link: Option<Vec<u8>>,
    pub xattrs: Xattrs,
    /// Size of a regular file's contents, which are compared separately.
    pub size: u64,
    /// Major and minor number of a character or block device.
    pub device: Option<(u32, u32)>,
}

/// Split a device number in the kernel's `new_encode_dev` format, used by
/// ext4 and erofs, into its major and minor number.
pub fn decode_device(dev: u32) -> (u32, u32) {
    (
        (dev & 0xf_ff00) >> 8,
        (dev & 0xff) | ((dev >> 12) & 0xf_ff00),
    )
}

/// Values longer than this are shown by size and digest.
const MAX_SHOWN_XATTR: usize = 128;

/// Show an extended attribute value: as text if it is printable (SELinux
/// labels end in a NUL), as hex otherwise, and by size and digest if it is long.
fn describe_xattr(value: Option<&Vec<u8>>) -> String {
    let Some(value) = value else {
        return "<none>".to_string();
    };
    let text = value.strip_suffix(b"\0").unwrap_or(value);
    if value.len() > MAX_SHOWN_XATTR {
        describe_contents(value)
    } else if !text.is_empty() && text.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        format!("\"{}\"", display(text))
    } else {
        format!("0x{}", hex::encode(value))
    }
}

impl Entry {
    /// Describe how `self` (rebuilt) differs from `other` (published), apart
    /// from the contents of regular files.
    fn differences(&self, other: &Self) -> Vec<String> {
        let mut out = Vec::new();
        if self.kind != other.kind {
            out.push(format!(
                "type {} vs {}",
                self.kind.name(),
                other.kind.name()
            ));
        }
        if self.mode != other.mode {
            out.push(format!("mode {:04o} vs {:04o}", self.mode, other.mode));
        }
        if self.uid != other.uid || self.gid != other.gid {
            out.push(format!(
                "owner {}:{} vs {}:{}",
                self.uid, self.gid, other.uid, other.gid
            ));
        }
        if self.link != other.link {
            let target = |l: &Option<Vec<u8>>| l.as_deref().map_or("<none>".to_string(), display);
            out.push(format!(
                "symlink target {} vs {}",
                target(&self.link),
                target(&other.link)
            ));
        }
        if self.device != other.device {
            let device = |d: Option<(u32, u32)>| {
                d.map_or("<none>".to_string(), |(major, minor)| {
                    format!("{major}:{minor}")
                })
            };
            out.push(format!(
                "device {} vs {}",
                device(self.device),
                device(other.device)
            ));
        }
        let mut names: Vec<_> = self.xattrs.keys().chain(other.xattrs.keys()).collect();
        names.sort();
        names.dedup();
        for name in names {
            let (e, a) = (self.xattrs.get(name), other.xattrs.get(name));
            if e != a {
                out.push(format!(
                    "xattr {} {} vs {}",
                    display(name),
                    describe_xattr(e),
                    describe_xattr(a)
                ));
            }
        }
        out
    }
}

/// A filesystem whose entries can be listed and whose files can be read.
pub trait FileTree {
    /// What `open` needs to find a file again.
    type Handle;

    /// Every entry, including the root directory, keyed by absolute path.
    fn entries(&self) -> Result<BTreeMap<FsPath, (Self::Handle, Entry)>>;

    /// Open a regular file to read its contents.
    fn open(&self, handle: &Self::Handle) -> Result<Box<dyn Read + '_>>;
}

/// The size and sha256 of a file's contents.
#[derive(PartialEq, Eq)]
struct ContentDigest {
    len: u64,
    sha256: [u8; 32],
}

impl ContentDigest {
    /// Hash up to `size` bytes from `reader`, without holding them in memory.
    fn of(reader: impl Read, size: u64) -> Result<Self> {
        let mut reader = reader.take(size);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut len = 0u64;
        loop {
            let n = reader
                .read(&mut buf)
                .whatever_context("failed to read file")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            len += n as u64;
        }
        Ok(Self {
            len,
            sha256: hasher.finalize().into(),
        })
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes, sha256 {}", self.len, hex::encode(self.sha256))
    }
}

fn read_contents(reader: impl Read, size: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    reader
        .take(size)
        .read_to_end(&mut out)
        .whatever_context("failed to read file")?;
    Ok(out)
}

/// A regular file in a tree: the tree, the file's handle and its size.
type TreeFile<'a, T> = (&'a T, &'a <T as FileTree>::Handle, u64);

/// Compare the contents of a regular file present in both trees.
///
/// Published files larger than both `size_limit` and the rebuilt file are
/// reported without being read, since a sparse or compressed file can claim
/// any size. Files that need a content-aware rule are read into memory, up to
/// `MAX_BUFFERED_SIZE`; all others are hashed as they are read.
fn compare_contents<E: FileTree, A: FileTree>(
    path: &[u8],
    (e_tree, e_handle, e_size): TreeFile<'_, E>,
    (a_tree, a_handle, a_size): TreeFile<'_, A>,
    rules: Rules,
    size_limit: u64,
) -> Result<FileReport> {
    if a_size > size_limit.max(e_size) {
        return Ok(report(
            path,
            FileStatus::Mismatch,
            format!(
                "published file is {a_size} bytes, more than the rebuilt file ({e_size} bytes) \
                 and its partition ({size_limit} bytes); not read"
            ),
        ));
    }
    let content_aware =
        rules == Rules::Root && (kmod::is_module(path) || path.ends_with(TUF_ROOT_ROLE));
    if content_aware {
        if e_size.max(a_size) > MAX_BUFFERED_SIZE {
            return Ok(report(
                path,
                FileStatus::Mismatch,
                format!(
                    "too large to compare ({e_size} vs {a_size} bytes, limit {MAX_BUFFERED_SIZE})"
                ),
            ));
        }
        let expected = read_contents(e_tree.open(e_handle)?, e_size)?;
        let actual = read_contents(a_tree.open(a_handle)?, a_size)?;
        return Ok(compare_file(path, Some(&expected), Some(&actual), rules));
    }
    let expected = ContentDigest::of(e_tree.open(e_handle)?, e_size)?;
    let actual = ContentDigest::of(a_tree.open(a_handle)?, a_size)?;
    Ok(if expected == actual {
        report(path, FileStatus::Match, "identical")
    } else {
        report(
            path,
            FileStatus::Mismatch,
            format!("contents differ ({expected} vs {actual})"),
        )
    })
}

/// Compare two filesystems entry by entry: type, permissions, ownership,
/// symlink targets, device numbers, extended attributes and file contents. Timestamps are not
/// compared. Identical entries are omitted.
///
/// `size_limit` bounds how much of a published file is read; see `compare_contents`.
pub fn compare_trees<E: FileTree, A: FileTree>(
    expected: &E,
    actual: &A,
    rules: Rules,
    size_limit: u64,
) -> Result<Vec<FileReport>> {
    let expected_entries = expected.entries()?;
    let actual_entries = actual.entries()?;
    let mut paths: Vec<&FsPath> = expected_entries
        .keys()
        .chain(actual_entries.keys())
        .collect();
    paths.sort();
    paths.dedup();

    let mut reports = Vec::new();
    for path in paths {
        let (e, a) = (expected_entries.get(path), actual_entries.get(path));
        let file = match (e, a) {
            (Some((e_handle, e)), Some((a_handle, a))) => {
                let differences = e.differences(a);
                if !differences.is_empty() {
                    report(path, FileStatus::Mismatch, differences.join("; "))
                } else if e.kind != Kind::File {
                    report(path, FileStatus::Match, "identical")
                } else {
                    compare_contents(
                        path,
                        (expected, e_handle, e.size),
                        (actual, a_handle, a.size),
                        rules,
                        size_limit,
                    )?
                }
            }
            (e, _) => {
                let side = if e.is_none() { "rebuilt" } else { "published" };
                report(
                    path,
                    FileStatus::Mismatch,
                    format!("missing from {side} image"),
                )
            }
        };
        if file.status != FileStatus::Match {
            reports.push(file);
        }
    }
    Ok(reports)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// Build a small FAT image containing `files` (paths relative to the root).
    pub fn fat_image(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut img = Cursor::new(vec![0u8; 1 << 20]);
        fatfs::format_volume(&mut img, fatfs::FormatVolumeOptions::new()).unwrap();
        {
            let fs = FileSystem::new(&mut img, FsOptions::new()).unwrap();
            for (path, contents) in files {
                let root = fs.root_dir();
                let (dirs, name) = path.rsplit_once('/').unwrap_or(("", path));
                let mut dir = root;
                for d in dirs.split('/').filter(|d| !d.is_empty()) {
                    dir = dir.create_dir(d).unwrap();
                }
                dir.create_file(name).unwrap().write_all(contents).unwrap();
            }
        }
        img.into_inner()
    }

    fn files(entries: &[(&str, Vec<u8>)]) -> Files {
        entries
            .iter()
            .map(|(p, c)| (p.as_bytes().to_vec(), c.clone()))
            .collect()
    }

    #[test]
    fn lists_fat_files() {
        let img = fat_image(&[("EFI/BOOT/bootx64.efi", b"MZshim"), ("top.txt", b"x")]);
        let files = fat_files(img).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[&b"/EFI/BOOT/bootx64.efi".to_vec()], b"MZshim");
        assert_eq!(files[&b"/top.txt".to_vec()], b"x");
    }

    #[test]
    fn rejects_duplicate_entries() {
        let mut map = BTreeMap::new();
        insert_unique(&mut map, b"/a".to_vec(), 1).unwrap();
        assert!(insert_unique(&mut map, b"/a".to_vec(), 2).is_err());
        // Names are compared as bytes, so names that only display alike stay distinct.
        insert_unique(&mut map, b"/\xff".to_vec(), 3).unwrap();
        insert_unique(&mut map, b"/\xfe".to_vec(), 4).unwrap();
        assert_eq!(display(b"/\xff"), display(b"/\xfe"));
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn classifies_differences() {
        let root = "a".repeat(64);
        let other_root = "b".repeat(64);
        let grub = |r: &str, s: &str| {
            format!(
                "set dm_verity_root=\"root,,,ro,0 8 verity 1 x y 4096 4096 1 1 sha256 {r} {s} 2\""
            )
            .into_bytes()
        };
        let expected = files(&[
            ("/same", b"same".to_vec()),
            ("/grub/grub.cfg", grub(&root, "00")),
            ("/grub/grub.cfg.sig", b"sig1".to_vec()),
            ("/other", b"one".to_vec()),
            ("/only-rebuilt", b"x".to_vec()),
        ]);
        let actual = files(&[
            ("/same", b"same".to_vec()),
            ("/grub/grub.cfg", grub(&other_root, "11")),
            ("/grub/grub.cfg.sig", b"sig2".to_vec()),
            ("/other", b"two".to_vec()),
        ]);
        let reports = compare_files(&expected, &actual, Rules::Boot);
        let status = |p: &str| reports.iter().find(|r| r.path == p).unwrap().status;
        assert!(reports.iter().all(|r| r.path != "/same"));
        assert_eq!(status("/grub/grub.cfg"), FileStatus::ExpectedDifference);
        assert_eq!(status("/grub/grub.cfg.sig"), FileStatus::ExpectedDifference);
        assert_eq!(status("/other"), FileStatus::Mismatch);
        assert_eq!(status("/only-rebuilt"), FileStatus::Mismatch);
    }

    #[test]
    fn root_rules_only_allow_module_signatures() {
        let sign = crate::kmod::tests::sign;
        let expected = files(&[
            ("/m/resigned.ko", sign(b"module", b"key1")),
            ("/m/changed.ko", sign(b"module", b"key1")),
            ("/m/unsigned.ko", b"module".to_vec()),
            ("/etc/ca.crt", b"ca1".to_vec()),
        ]);
        let actual = files(&[
            ("/m/resigned.ko", sign(b"module", b"key2")),
            ("/m/changed.ko", sign(b"modulf", b"key2")),
            ("/m/unsigned.ko", sign(b"module", b"key2")),
            ("/etc/ca.crt", b"ca2".to_vec()),
        ]);
        let reports = compare_files(&expected, &actual, Rules::Root);
        let status = |p: &str| reports.iter().find(|r| r.path == p).unwrap().status;
        assert_eq!(status("/m/resigned.ko"), FileStatus::ExpectedDifference);
        assert_eq!(status("/m/changed.ko"), FileStatus::Mismatch);
        assert_eq!(status("/m/unsigned.ko"), FileStatus::Mismatch);
        // Certificates are only signing artifacts in the boot partitions.
        assert_eq!(status("/etc/ca.crt"), FileStatus::Mismatch);
    }

    #[test]
    fn root_role_differences_are_expected() {
        let root = |key: &str| {
            format!(
                r#"{{"signed":{{"_type":"root","version":1,"expires":"2027-10-12T17:12:35Z","keys":{{"{key}":{{}}}},"roles":{{}}}},"signatures":[]}}"#
            )
            .into_bytes()
        };
        let path = "/aarch64-bottlerocket-linux-gnu/sys-root/usr/share/updog/root.json";
        let expected = files(&[(path, root("aaaa"))]);
        let actual = files(&[(path, root("bbbb"))]);
        let reports = compare_files(&expected, &actual, Rules::Root);
        assert_eq!(reports[0].status, FileStatus::ExpectedDifference);
        assert!(
            reports[0].detail.contains("keys bbbb"),
            "{}",
            reports[0].detail
        );
        assert!(
            reports[0].detail.contains("sha512 "),
            "{}",
            reports[0].detail
        );

        // Anything that is not a root role still fails.
        let actual = files(&[(path, br#"{"signed":{"_type":"targets"}}"#.to_vec())]);
        let reports = compare_files(&expected, &actual, Rules::Root);
        assert_eq!(reports[0].status, FileStatus::Mismatch);
    }

    #[test]
    fn only_key_sections_are_expected_pe_differences() {
        let names = |n: &[&str]| Ok(n.iter().map(|s| s.to_string()).collect());
        let (status, detail) = describe_pe_difference(names(&[".vendor_cert"]));
        assert_eq!(status, FileStatus::ExpectedDifference);
        assert!(detail.starts_with("differs only"), "{detail}");

        let (status, _) = describe_pe_difference(names(&[".pubkey"]));
        assert_eq!(status, FileStatus::ExpectedDifference);

        let (status, detail) = describe_pe_difference(names(&[".text", ".vendor_cert"]));
        assert_eq!(status, FileStatus::Mismatch);
        assert!(detail.contains(".text, .vendor_cert"), "{detail}");

        let (status, detail) = describe_pe_difference(names(&[]));
        assert_eq!(status, FileStatus::Mismatch);
        assert!(detail.contains("headers"), "{detail}");

        let (status, _) =
            describe_pe_difference(Err(snafu::FromString::without_source("bad".to_string())));
        assert_eq!(status, FileStatus::Mismatch);
    }

    #[test]
    fn reports_xattr_differences() {
        let entry = |xattrs: &[(&str, &[u8])]| Entry {
            kind: Kind::File,
            mode: 0o755,
            uid: 0,
            gid: 0,
            link: None,
            xattrs: xattrs
                .iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), v.to_vec()))
                .collect(),
            size: 0,
            device: None,
        };
        let label: &[u8] = b"system_u:object_r:os_t:s0\0";
        let rebuilt = entry(&[("security.selinux", label)]);
        assert!(rebuilt.differences(&rebuilt.clone()).is_empty());

        let relabeled = entry(&[("security.selinux", b"system_u:object_r:any_t:s0\0")]);
        assert_eq!(
            rebuilt.differences(&relabeled),
            [
                r#"xattr security.selinux "system_u:object_r:os_t:s0" vs "system_u:object_r:any_t:s0""#
            ]
        );

        let capable = entry(&[
            ("security.capability", &[1, 0, 0, 2, 0, 0x20, 0, 0]),
            ("security.selinux", label),
        ]);
        assert_eq!(
            rebuilt.differences(&capable),
            ["xattr security.capability <none> vs 0x0100000200200000"]
        );
    }

    /// An in-memory tree whose files can be opened, for testing `compare_trees`.
    struct MemTree(BTreeMap<FsPath, (Vec<u8>, Entry)>);

    impl FileTree for MemTree {
        type Handle = Vec<u8>;

        fn entries(&self) -> Result<BTreeMap<FsPath, (Vec<u8>, Entry)>> {
            Ok(self.0.clone())
        }

        fn open(&self, handle: &Vec<u8>) -> Result<Box<dyn Read + '_>> {
            Ok(Box::new(Cursor::new(handle.clone())))
        }
    }

    fn mem_tree(files: &[(&str, &[u8], u64)]) -> MemTree {
        MemTree(
            files
                .iter()
                .map(|(path, contents, size)| {
                    let entry = Entry {
                        kind: Kind::File,
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                        link: None,
                        xattrs: Xattrs::new(),
                        size: *size,
                        device: None,
                    };
                    (path.as_bytes().to_vec(), (contents.to_vec(), entry))
                })
                .collect(),
        )
    }

    #[test]
    fn compares_tree_contents_by_digest() {
        let expected = mem_tree(&[("/a", b"one", 3), ("/b", b"two", 3), ("/c", b"3", 1)]);
        let actual = mem_tree(&[("/a", b"one", 3), ("/b", b"tw0", 3), ("/c", b"three", 5)]);
        let reports = compare_trees(&expected, &actual, Rules::Root, 1 << 20).unwrap();
        assert_eq!(reports.len(), 2, "{reports:?}");
        assert_eq!(reports[0].path, "/b");
        assert_eq!(reports[0].status, FileStatus::Mismatch);
        assert!(
            reports[0].detail.contains("3 bytes, sha256 "),
            "{reports:?}"
        );
        assert!(reports[1].detail.contains("vs 5 bytes"), "{reports:?}");
    }

    #[test]
    fn does_not_read_oversized_published_files() {
        let expected = mem_tree(&[("/big", b"", 0)]);
        // The handle is empty, so reading it would hash nothing; the size alone fails it.
        let actual = mem_tree(&[("/big", b"", 1 << 40)]);
        let reports = compare_trees(&expected, &actual, Rules::Root, 1 << 20).unwrap();
        assert_eq!(reports[0].status, FileStatus::Mismatch);
        assert!(reports[0].detail.contains("not read"), "{reports:?}");
    }
}
