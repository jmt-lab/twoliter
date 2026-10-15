//! File-level comparison of partitions whose bytes are expected to differ.

use crate::error::Result;
use crate::kmod;
use ext4_view::Ext4;
use fatfs::{FileSystem, FsOptions};
use regex::bytes::Regex;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use snafu::{ensure_whatever, OptionExt, ResultExt};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Cursor, Read};
use std::sync::LazyLock;

/// Signatures and signing certificates, which may differ if both images have them.
const SIGNING_ARTIFACT_SUFFIXES: &[&str] = &[".sig", ".crt", ".cer", ".der", ".auth", ".esl"];

/// FIPS HMACs of boot files, written by `openssl sha512 -hmac`.
const HMAC_SUFFIX: &[u8] = b".hmac";

/// The well-known key of the FIPS boot file HMACs.
const HMAC_KEY: &[u8] = b"FIPS-FTW-RHT2009";

/// The GRUB configuration in BOOT-A, which holds the kernel command line.
pub const GRUB_CFG: &[u8] = b"/grub/grub.cfg";

/// Where the firmware finds the UKI on the EFI system partition of a UKI image.
pub const UKI_PATHS: &[&str] = &["/EFI/BOOT/BOOTX64.EFI", "/EFI/BOOT/BOOTAA64.EFI"];

/// Whether `path` is where the firmware finds a UKI. FAT names are case-insensitive.
pub fn is_uki_path(path: &[u8]) -> bool {
    UKI_PATHS
        .iter()
        .any(|u| path.eq_ignore_ascii_case(u.as_bytes()))
}

/// The TUF root role, which rebuilds cannot reproduce without the release keys.
const TUF_ROOT_ROLE: &[u8] = b"/usr/share/updog/root.json";

/// The SBOMs in ROOT-A, which sbomtool cannot reproduce yet.
const SBOMS: &[&[u8]] = &[
    b"/usr/share/bottlerocket/spdx-sbom.json",
    b"/usr/share/bottlerocket/cyclonedx-sbom.json",
];

/// PE sections that only hold embedded keys.
const KEY_SECTIONS: &[&str] = &[".vendor_cert", ".pubkey"];

/// The PE section of a UKI that holds the kernel command line.
pub const CMDLINE_SECTION: &str = ".cmdline";

/// Largest file read into memory for a content-aware comparison.
const MAX_BUFFERED_SIZE: u64 = 256 << 20;

/// Which differences are expected in a filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rules {
    /// EFI-A and BOOT-A: signing-dependent content.
    Boot,
    /// ROOT-A: module signatures, the TUF root role and the SBOMs.
    Root,
    /// PRIVATE: none; compared only to explain a difference.
    Exact,
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

/// Insert `value` at `key`, failing if it is already present.
pub fn insert_unique<V>(map: &mut BTreeMap<Vec<u8>, V>, key: Vec<u8>, value: V) -> Result<()> {
    ensure_whatever!(!map.contains_key(&key), "duplicate entry {}", display(&key));
    map.insert(key, value);
    Ok(())
}

/// Bounds the file data read from a partition to the partition's size.
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

/// Offset of the primary ext4 superblock, and the size of every copy.
const EXT4_SUPERBLOCK: usize = 1024;

/// `s_flags` bits recording the directory hash signedness: EXT2_FLAGS_SIGNED_HASH and
/// EXT2_FLAGS_UNSIGNED_HASH.
const EXT4_DIR_HASH_FLAGS: u32 = 0x3;

/// Offset of `s_flags` in an ext4 superblock.
const EXT4_S_FLAGS: usize = 0x160;

/// Offset of `s_checksum` in an ext4 superblock, which covers the bytes before it.
const EXT4_S_CHECKSUM: usize = 0x3fc;

fn le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().expect("4 bytes"))
}

/// The ext4 superblock at `offset` in `partition`.
fn ext4_superblock(partition: &[u8], offset: usize) -> Result<&[u8]> {
    let sb = partition
        .get(offset..offset + EXT4_SUPERBLOCK)
        .whatever_context("ext4 filesystem is truncated")?;
    ensure_whatever!(
        sb[0x38..0x3a] == [0x53, 0xef],
        "no ext4 superblock at offset {offset}"
    );
    Ok(sb)
}

/// The offsets of the primary superblock and of each backup.
fn ext4_superblock_offsets(partition: &[u8]) -> Result<Vec<usize>> {
    let sb = ext4_superblock(partition, EXT4_SUPERBLOCK)?;
    let (compat, incompat, ro_compat) = (le_u32(sb, 0x5c), le_u32(sb, 0x60), le_u32(sb, 0x64));
    let log_block_size = le_u32(sb, 0x18);
    ensure_whatever!(log_block_size <= 6, "invalid ext4 block size");
    let block_size = 1024u64 << log_block_size;
    let mut blocks = u64::from(le_u32(sb, 0x4));
    // INCOMPAT_64BIT
    if incompat & 0x80 != 0 {
        blocks |= u64::from(le_u32(sb, 0x150)) << 32;
    }
    let first_data_block = u64::from(le_u32(sb, 0x14));
    let blocks_per_group = u64::from(le_u32(sb, 0x20));
    ensure_whatever!(blocks_per_group > 0, "invalid ext4 blocks per group");
    let groups = blocks
        .saturating_sub(first_data_block)
        .div_ceil(blocks_per_group);
    let is_power = |mut g: u64, base: u64| {
        while g.is_multiple_of(base) {
            g /= base;
        }
        g == 1
    };
    let has_backup = |g: u64| {
        // COMPAT_SPARSE_SUPER2 keeps at most two backups, at the groups it names.
        if compat & 0x200 != 0 {
            g == u64::from(le_u32(sb, 0x24c)) || g == u64::from(le_u32(sb, 0x250))
        // RO_COMPAT_SPARSE_SUPER keeps them in group 1 and powers of 3, 5 and 7.
        } else if ro_compat & 0x1 != 0 {
            g == 1 || is_power(g, 3) || is_power(g, 5) || is_power(g, 7)
        } else {
            true
        }
    };
    let mut offsets = vec![EXT4_SUPERBLOCK];
    for g in (1..groups).filter(|g| has_backup(*g)) {
        let offset = g
            .checked_mul(blocks_per_group)
            .and_then(|b| b.checked_add(first_data_block))
            .and_then(|b| b.checked_mul(block_size))
            .and_then(|o| usize::try_from(o).ok())
            .whatever_context("invalid ext4 backup superblock offset")?;
        ext4_superblock(partition, offset)?;
        offsets.push(offset);
    }
    Ok(offsets)
}

/// CRC32C without the final inversion, as ext4 checksums use it.
fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & (crc & 1).wrapping_neg());
        }
    }
    crc
}

fn ext4_superblock_checksum(sb: &[u8]) -> u32 {
    crc32c(!0, &sb[..EXT4_S_CHECKSUM])
}

/// The directory hash flags of the primary ext4 superblock.
pub fn ext4_dir_hash_flags(partition: &[u8]) -> Result<u32> {
    let sb = ext4_superblock(partition, EXT4_SUPERBLOCK)?;
    Ok(le_u32(sb, EXT4_S_FLAGS) & EXT4_DIR_HASH_FLAGS)
}

/// How directory hash flags read in reports.
pub fn dir_hash_signedness(flags: u32) -> Option<&'static str> {
    match flags & EXT4_DIR_HASH_FLAGS {
        0x1 => Some("signed"),
        0x2 => Some("unsigned"),
        0x3 => Some("flagged both signed and unsigned"),
        _ => None,
    }
}

/// Give every superblock of `partition`, primary and backups, the directory hash
/// flags of the superblock at the same offset in `like`. Superblocks with a valid
/// checksum get the checksum of their new contents, so the result is what a build
/// host whose `char` has the signedness `like` records writes.
pub fn ext4_copy_dir_hash_flags(partition: &mut [u8], like: &[u8]) -> Result<()> {
    let sb = ext4_superblock(partition, EXT4_SUPERBLOCK)?;
    // RO_COMPAT_METADATA_CSUM
    let checksummed = le_u32(sb, 0x64) & 0x400 != 0;
    for offset in ext4_superblock_offsets(partition)? {
        // Without a superblock there, `like` differs anyway.
        let Ok(like_sb) = ext4_superblock(like, offset) else {
            continue;
        };
        let flags = le_u32(like_sb, EXT4_S_FLAGS) & EXT4_DIR_HASH_FLAGS;
        let sb = &mut partition[offset..offset + EXT4_SUPERBLOCK];
        let valid_checksum =
            checksummed && ext4_superblock_checksum(sb) == le_u32(sb, EXT4_S_CHECKSUM);
        let s_flags = (le_u32(sb, EXT4_S_FLAGS) & !EXT4_DIR_HASH_FLAGS) | flags;
        sb[EXT4_S_FLAGS..EXT4_S_FLAGS + 4].copy_from_slice(&s_flags.to_le_bytes());
        if valid_checksum {
            let checksum = ext4_superblock_checksum(sb);
            sb[EXT4_S_CHECKSUM..].copy_from_slice(&checksum.to_le_bytes());
        }
    }
    Ok(())
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
                // Sparse files and hardlinks can claim more than the partition holds.
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

/// Compare a PE binary. Only signatures, key sections and, if `cmdline_checked`,
/// the verity digests in `.cmdline` may differ.
fn compare_pe(expected: &[u8], actual: &[u8], cmdline_checked: bool) -> (FileStatus, String) {
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
    let sections = differing_sections(expected, actual, cmdline_checked);
    let (mut status, mut detail) = describe_pe_difference(&sections);
    if status == FileStatus::ExpectedDifference {
        let allowed: BTreeSet<_> = sections
            .iter()
            .flatten()
            .map(|s| (s.name.clone(), s.occurrence))
            .collect();
        let same_beyond_sections =
            normalize_pe(expected, &allowed).and_then(|e| Ok(e == normalize_pe(actual, &allowed)?));
        match same_beyond_sections {
            Ok(true) => {}
            Ok(false) => {
                status = FileStatus::Mismatch;
                detail = format!("{detail}, but its headers or layout differ too");
            }
            Err(e) => {
                status = FileStatus::Mismatch;
                detail = format!("{detail}, but its headers could not be compared: {e}");
            }
        }
    }
    (
        status,
        format!("Authenticode digests differ ({e} vs {a}); {detail}"),
    )
}

/// A PE section whose contents differ, with why that is expected, if it is.
#[derive(Debug)]
struct SectionDifference {
    name: String,
    /// Which section of that name this is, counting from 1.
    occurrence: usize,
    expected: Option<&'static str>,
}

impl SectionDifference {
    fn new(
        (name, occurrence): &(String, usize),
        expected: Option<&[u8]>,
        actual: Option<&[u8]>,
        cmdline_checked: bool,
    ) -> Self {
        let expected = match (expected, actual) {
            (Some(_), Some(_)) if KEY_SECTIONS.contains(&name.as_str()) => {
                Some("sections holding embedded keys")
            }
            // BOOT-CONFIG checks the rest of the command line.
            (Some(e), Some(a))
                if cmdline_checked
                    && name == CMDLINE_SECTION
                    && normalize_verity(e) == normalize_verity(a) =>
            {
                Some("the verity root hash and salt of the kernel command line")
            }
            _ => None,
        };
        Self {
            name: name.clone(),
            occurrence: *occurrence,
            expected,
        }
    }
}

/// Classify the section differences of PE files with different Authenticode digests.
fn describe_pe_difference(sections: &Result<Vec<SectionDifference>>) -> (FileStatus, String) {
    let names = |sections: &[&SectionDifference]| {
        sections
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    match sections {
        Ok(sections) if sections.is_empty() => (
            FileStatus::Mismatch,
            "no section differs, so the headers do".to_string(),
        ),
        Ok(sections) if sections.iter().all(|s| s.expected.is_some()) => {
            let mut reasons: Vec<(&str, Vec<&SectionDifference>)> = Vec::new();
            for s in sections {
                let reason = s.expected.expect("checked above");
                match reasons.iter_mut().find(|(r, _)| *r == reason) {
                    Some((_, list)) => list.push(s),
                    None => reasons.push((reason, vec![s])),
                }
            }
            let reasons: Vec<String> = reasons
                .iter()
                .map(|(reason, sections)| format!("{reason} ({})", names(sections)))
                .collect();
            (
                FileStatus::ExpectedDifference,
                format!("differs only in {}", reasons.join(" and ")),
            )
        }
        Ok(sections) => (
            FileStatus::Mismatch,
            format!(
                "differs in sections {}; only signatures and the sections holding embedded keys \
                 may differ",
                names(&sections.iter().collect::<Vec<_>>())
            ),
        ),
        Err(e) => (
            FileStatus::Mismatch,
            format!("sections could not be compared: {e}"),
        ),
    }
}

/// Key PE sections by name and occurrence, so same-named sections stay apart.
fn by_occurrence(sections: Vec<(String, &[u8])>) -> Vec<((String, usize), &[u8])> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    sections
        .into_iter()
        .map(|(name, data)| {
            let n = seen.entry(name.clone()).or_default();
            *n += 1;
            ((name, *n), data)
        })
        .collect()
}

/// The PE sections that differ, including those in only one binary.
fn differing_sections(
    expected: &[u8],
    actual: &[u8],
    cmdline_checked: bool,
) -> Result<Vec<SectionDifference>> {
    let sections = |data, side: &str| -> Result<BTreeMap<_, _>> {
        let sections = pcrsys::pe::sections(data)
            .with_whatever_context(|_| format!("failed to read {side} PE sections"))?;
        Ok(by_occurrence(sections).into_iter().collect())
    };
    let expected = sections(expected, "rebuilt")?;
    let actual = sections(actual, "published")?;
    let mut keys: Vec<_> = expected.keys().chain(actual.keys()).collect();
    keys.sort();
    keys.dedup();
    Ok(keys
        .into_iter()
        .filter(|k| expected.get(*k) != actual.get(*k))
        .map(|k| {
            SectionDifference::new(
                k,
                expected.get(k).copied(),
                actual.get(k).copied(),
                cmdline_checked,
            )
        })
        .collect())
}

/// `data` without its checksum, signatures, or the `allowed` sections' contents
/// and virtual sizes.
fn normalize_pe(data: &[u8], allowed: &BTreeSet<(String, usize)>) -> Result<Vec<u8>> {
    let u16_at = |at: usize| -> Result<usize> {
        let b = data
            .get(at..at + 2)
            .whatever_context("truncated PE headers")?;
        Ok(u16::from_le_bytes([b[0], b[1]]).into())
    };
    let u32_at = |at: usize| -> Result<usize> {
        let b = data
            .get(at..at + 4)
            .whatever_context("truncated PE headers")?;
        Ok(u32::from_le_bytes(b.try_into().expect("4 bytes")) as usize)
    };
    let mut out = data.to_vec();
    let clear = |out: &mut Vec<u8>, at: usize, len: usize| -> Result<()> {
        out.get_mut(at..at.saturating_add(len))
            .whatever_context("PE field or section beyond the end of the file")?
            .fill(0);
        Ok(())
    };

    let coff = u32_at(0x3c)? + 4;
    ensure_whatever!(
        data.get(coff - 4..coff) == Some(b"PE\0\0"),
        "no PE signature"
    );
    let optional = coff + 20;
    ensure_whatever!(u16_at(optional)? == 0x20b, "not a PE32+ binary");
    clear(&mut out, optional + 64, 4)?; // CheckSum
    let certificates = optional + 112 + 4 * 8; // data directory 4
    let (cert_offset, cert_len) = (u32_at(certificates)?, u32_at(certificates + 4)?);
    clear(&mut out, certificates, 8)?;

    let names = pcrsys::pe::sections(data).whatever_context("failed to read PE sections")?;
    let section_table = optional + u16_at(coff + 16)?;
    ensure_whatever!(
        names.len() == u16_at(coff + 2)?,
        "section table and sections disagree"
    );
    for (i, (key, _)) in by_occurrence(names).iter().enumerate() {
        if allowed.contains(key) {
            let header = section_table + i * 40;
            clear(&mut out, header + 8, 4)?; // VirtualSize
            clear(&mut out, u32_at(header + 20)?, u32_at(header + 16)?)?;
        }
    }
    // Signatures differ in length, so remove the certificate table.
    if cert_len > 0 {
        let end = cert_offset
            .checked_add(cert_len)
            .filter(|end| *end <= out.len())
            .whatever_context("certificate table beyond the end of the file")?;
        out.drain(cert_offset..end);
    }
    Ok(out)
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

/// Describe the published TUF root role so it can be checked by hand.
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

/// The packages an SBOM lists, by name and version, with how often each is listed.
type SbomPackages = BTreeMap<(String, String), usize>;

fn is_sbom(path: &[u8]) -> bool {
    SBOMS.iter().any(|s| path.ends_with(s))
}

/// The format and packages of an SPDX or CycloneDX SBOM.
fn sbom_packages(data: &[u8]) -> Option<(&'static str, SbomPackages)> {
    fn field(v: &Value, name: &str) -> String {
        v.get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }
    fn components(list: &[Value], out: &mut SbomPackages) -> Option<()> {
        for c in list {
            *out.entry((field(c, "name"), field(c, "version")))
                .or_default() += 1;
            if let Some(nested) = c.get("components") {
                components(nested.as_array()?, out)?;
            }
        }
        Some(())
    }
    let doc = serde_json::from_slice::<Value>(data).ok()?;
    let mut packages = SbomPackages::new();
    if doc.get("spdxVersion").is_some() {
        for p in doc.get("packages")?.as_array()? {
            *packages
                .entry((field(p, "name"), field(p, "versionInfo")))
                .or_default() += 1;
        }
        Some(("SPDX", packages))
    } else if doc.get("bomFormat")?.as_str()? == "CycloneDX" {
        components(doc.get("components")?.as_array()?, &mut packages)?;
        Some(("CycloneDX", packages))
    } else {
        None
    }
}

/// Compare SBOMs, which may differ if they list the same packages.
fn compare_sbom(expected: &[u8], actual: &[u8]) -> (FileStatus, String) {
    let (Some((e_format, e_packages)), Some((a_format, a_packages))) =
        (sbom_packages(expected), sbom_packages(actual))
    else {
        return (
            FileStatus::Mismatch,
            format!(
                "not both SPDX or CycloneDX SBOMs ({} vs {})",
                describe_contents(expected),
                describe_contents(actual)
            ),
        );
    };
    if e_format != a_format {
        return (
            FileStatus::Mismatch,
            format!("{e_format} SBOM rebuilt but {a_format} SBOM published"),
        );
    }
    let count = |packages: &SbomPackages| packages.values().sum::<usize>();
    if e_packages != a_packages {
        // Packages listed more often in `a` than in `b`, up to a few.
        let more = |a: &SbomPackages, b: &SbomPackages| {
            let names: Vec<_> = a
                .iter()
                .filter(|(k, n)| b.get(*k).is_none_or(|m| m < *n))
                .map(|((name, version), _)| format!("{name} {version}"))
                .collect();
            match names.len() {
                0 => "none".to_string(),
                n if n > 5 => format!("{} and {} more", names[..5].join(", "), n - 5),
                _ => names.join(", "),
            }
        };
        return (
            FileStatus::Mismatch,
            format!(
                "{e_format} SBOMs list different packages ({} rebuilt, {} published); only or \
                 more often in the rebuilt SBOM: {}; in the published SBOM: {}",
                count(&e_packages),
                count(&a_packages),
                more(&e_packages, &a_packages),
                more(&a_packages, &e_packages)
            ),
        );
    }
    (
        FileStatus::ExpectedDifference,
        format!(
            "{e_format} SBOM listing the same {} packages; sbomtool records the time it ran, \
             random document IDs and CPEs in a random order, so the rest is not compared",
            count(&a_packages)
        ),
    )
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
    let (expected, actual) = match (expected, actual) {
        (Some(e), Some(a)) => (e, a),
        (None, _) => return report(path, FileStatus::Mismatch, "missing from rebuilt image"),
        (_, None) => return report(path, FileStatus::Mismatch, "missing from published image"),
    };

    if expected == actual {
        return report(path, FileStatus::Match, "identical");
    }
    match rules {
        Rules::Boot => {
            let signing_artifact = SIGNING_ARTIFACT_SUFFIXES
                .iter()
                .any(|s| path.to_ascii_lowercase().ends_with(s.as_bytes()));
            if signing_artifact {
                return report(path, FileStatus::ExpectedDifference, "signing artifact");
            }
            if is_pe(expected) && is_pe(actual) {
                let (status, detail) = compare_pe(expected, actual, is_uki_path(path));
                return report(path, status, detail);
            }
            // BOOT-CONFIG checks the rest of grub.cfg.
            if path == GRUB_CFG && normalize_verity(expected) == normalize_verity(actual) {
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
            if is_sbom(path) {
                let (status, detail) = compare_sbom(expected, actual);
                return report(path, status, detail);
            }
        }
        Rules::Exact => {}
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

/// HMAC-SHA512 of `data` with `key`, as `openssl sha512 -hmac` computes it.
fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    const BLOCK_SIZE: usize = 128;
    let mut block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        block[..64].copy_from_slice(&Sha512::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.map(|b| b ^ byte);
    let inner = Sha512::new()
        .chain_update(pad(0x36))
        .chain_update(data)
        .finalize();
    Sha512::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

/// Check that a FIPS HMAC, whose key is public, is the HMAC of the published
/// file it names.
fn compare_hmac(path: &[u8], expected: &[u8], actual: &[u8], published: &Files) -> FileReport {
    // `<hex digest>  <path from the partition root>`
    let parse = |data: &[u8]| -> Option<(String, String)> {
        let text = std::str::from_utf8(data).ok()?.trim_end_matches('\n');
        let (digest, target) = text.split_once("  ")?;
        Some((digest.to_string(), target.to_string()))
    };
    let (Some((_, rebuilt_target)), Some((digest, target))) = (parse(expected), parse(actual))
    else {
        return report(
            path,
            FileStatus::Mismatch,
            format!(
                "not an HMAC of the form `<digest>  <path>` ({} vs {})",
                describe_contents(expected),
                describe_contents(actual)
            ),
        );
    };
    if target != rebuilt_target {
        return report(
            path,
            FileStatus::Mismatch,
            format!("covers {target} instead of {rebuilt_target}"),
        );
    }
    let target_path = format!("/{target}");
    // FAT names are case-insensitive.
    let targets: Vec<_> = published
        .iter()
        .filter(|(p, _)| p.eq_ignore_ascii_case(target_path.as_bytes()))
        .collect();
    let [(_, data)] = targets.as_slice() else {
        return report(
            path,
            FileStatus::Mismatch,
            format!("the published image has no single {target_path} to check it against"),
        );
    };
    let computed = hex::encode(hmac_sha512(HMAC_KEY, data));
    if digest.eq_ignore_ascii_case(&computed) && expected == actual {
        report(path, FileStatus::Match, "identical")
    } else if digest.eq_ignore_ascii_case(&computed) {
        report(
            path,
            FileStatus::ExpectedDifference,
            format!("HMAC of the published {target_path}, which differs from the rebuilt one"),
        )
    } else {
        report(
            path,
            FileStatus::Mismatch,
            format!(
                "is not the HMAC of the published {target_path} ({digest} vs computed {computed})"
            ),
        )
    }
}

/// Compare all files; identical ones are logged but not returned.
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
            match (e, a) {
                (Some(e), Some(a))
                    if rules == Rules::Boot && p.to_ascii_lowercase().ends_with(HMAC_SUFFIX) =>
                {
                    compare_hmac(p, e, a, actual)
                }
                _ => compare_file(p, e, a, rules),
            }
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

/// Split a `new_encode_dev` device number into its major and minor number.
pub fn decode_device(dev: u32) -> (u32, u32) {
    (
        (dev & 0xf_ff00) >> 8,
        (dev & 0xff) | ((dev >> 12) & 0xf_ff00),
    )
}

/// Values longer than this are shown by size and digest.
const MAX_SHOWN_XATTR: usize = 128;

/// Show an xattr value as text, hex, or by size and digest if it is long.
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
    /// How `self` (rebuilt) differs from `other` (published), apart from contents.
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

/// Compare a regular file in both trees. Published files larger than both
/// `size_limit` and the rebuilt file are not read.
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
    let content_aware = rules == Rules::Root
        && (kmod::is_module(path) || path.ends_with(TUF_ROOT_ROLE) || is_sbom(path));
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

/// Compare two filesystems entry by entry, apart from timestamps. Identical
/// entries are omitted.
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
    use serde_json::json;
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
    #[ignore = "needs mkfs.ext4"]
    fn finds_ext4_superblocks_like_dumpe2fs() {
        use std::process::Command;
        let dir = tempfile::tempdir().unwrap();
        let fs = dir.path().join("fs");
        for (options, size) in [
            (&["-b", "1024"][..], "10M"),
            (&["-b", "1024"], "60M"),
            (&["-b", "4096"], "200M"),
            (&["-b", "1024", "-O", "^sparse_super,^resize_inode"], "30M"),
            (&["-b", "1024", "-O", "sparse_super2"], "60M"),
            (&["-b", "1024", "-O", "64bit"], "30M"),
        ] {
            let _ = std::fs::remove_file(&fs);
            let output = Command::new("mkfs.ext4")
                .arg("-q")
                .args(options)
                .arg(&fs)
                .arg(size)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let output = Command::new("dumpe2fs").arg(&fs).output().unwrap();
            assert!(output.status.success(), "{output:?}");
            let block_size: usize = options[1].parse().unwrap();
            // "  Primary superblock at 1, ..." and "  Backup superblock at 8193, ...".
            let expected: Vec<usize> = String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .filter_map(|l| l.trim().split_once("superblock at "))
                .map(|(_, rest)| {
                    let block: usize = rest.split(',').next().unwrap().parse().unwrap();
                    if block <= 1 {
                        EXT4_SUPERBLOCK
                    } else {
                        block * block_size
                    }
                })
                .collect();
            let image = std::fs::read(&fs).unwrap();
            assert_eq!(
                ext4_superblock_offsets(&image).unwrap(),
                expected,
                "{options:?} {size}"
            );
        }
    }

    #[test]
    #[ignore = "needs mkfs.ext4"]
    fn copies_dir_hash_flags_into_every_superblock() {
        use std::process::Command;
        let dir = tempfile::tempdir().unwrap();
        let fs = dir.path().join("fs");
        let output = Command::new("mkfs.ext4")
            .args(["-q", "-b", "1024"])
            .arg(&fs)
            .arg("30M")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let image = std::fs::read(&fs).unwrap();
        let offsets = ext4_superblock_offsets(&image).unwrap();
        assert!(offsets.len() > 2, "{offsets:?}");

        // Each copy of `like` records the opposite signedness.
        let mut like = image.clone();
        for offset in &offsets {
            let s_flags = offset + EXT4_S_FLAGS;
            like[s_flags] ^= 0x3;
            let checksum = ext4_superblock_checksum(&like[*offset..offset + EXT4_SUPERBLOCK]);
            like[offset + EXT4_S_CHECKSUM..offset + EXT4_SUPERBLOCK]
                .copy_from_slice(&checksum.to_le_bytes());
        }
        assert_ne!(
            ext4_dir_hash_flags(&like).unwrap(),
            ext4_dir_hash_flags(&image).unwrap()
        );
        let mut copied = image.clone();
        ext4_copy_dir_hash_flags(&mut copied, &like).unwrap();
        assert!(copied == like);

        // e2fsck accepts the superblock checksums.
        std::fs::write(&fs, &copied).unwrap();
        let output = Command::new("e2fsck").arg("-fn").arg(&fs).output().unwrap();
        assert!(output.status.success(), "{output:?}");
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

    const SPDX_SBOM: &str =
        "/x86_64-bottlerocket-linux-gnu/sys-root/usr/share/bottlerocket/spdx-sbom.json";
    const CYCLONEDX_SBOM: &str =
        "/x86_64-bottlerocket-linux-gnu/sys-root/usr/share/bottlerocket/cyclonedx-sbom.json";

    /// An SPDX SBOM created at `created`, listing `packages` by name and version.
    fn spdx(created: &str, packages: &[(&str, &str)]) -> Vec<u8> {
        let packages: Vec<_> = packages
            .iter()
            .map(|(name, version)| json!({ "name": name, "versionInfo": version }))
            .collect();
        serde_json::to_vec(&json!({
            "spdxVersion": "SPDX-2.3",
            "creationInfo": { "created": created },
            "documentNamespace": format!("https://anchore.com/{created}"),
            "packages": packages,
        }))
        .unwrap()
    }

    #[test]
    fn sbom_differences_are_expected_for_the_same_packages() {
        let packages = [("glibc", "2.41"), ("kernel", "6.12.1")];
        let expected = files(&[(SPDX_SBOM, spdx("2026-10-22T23:31:05Z", &packages))]);
        let actual = files(&[(SPDX_SBOM, spdx("2026-10-28T22:19:59Z", &packages))]);
        let reports = compare_files(&expected, &actual, Rules::Root);
        assert_eq!(reports[0].status, FileStatus::ExpectedDifference);
        assert!(
            reports[0]
                .detail
                .starts_with("SPDX SBOM listing the same 2 packages"),
            "{}",
            reports[0].detail
        );

        // Nested CycloneDX components count as packages.
        let cyclonedx = |serial: &str, nested: &str| {
            serde_json::to_vec(&json!({
                "bomFormat": "CycloneDX",
                "serialNumber": serial,
                "components": [{
                    "name": "aws-k8s", "version": "1.68.0",
                    "components": [{ "name": nested, "version": "1" }],
                }],
            }))
            .unwrap()
        };
        let expected = files(&[(CYCLONEDX_SBOM, cyclonedx("urn:uuid:1", "a"))]);
        let actual = files(&[(CYCLONEDX_SBOM, cyclonedx("urn:uuid:2", "a"))]);
        let reports = compare_files(&expected, &actual, Rules::Root);
        assert_eq!(reports[0].status, FileStatus::ExpectedDifference);
        let actual = files(&[(CYCLONEDX_SBOM, cyclonedx("urn:uuid:2", "b"))]);
        let reports = compare_files(&expected, &actual, Rules::Root);
        assert_eq!(reports[0].status, FileStatus::Mismatch);

        // Read from a tree, as ROOT-A is.
        let (e, a) = (
            spdx("2026-10-22T23:31:05Z", &packages),
            spdx("2026-10-28T22:19:59Z", &packages),
        );
        let reports = compare_trees(
            &mem_tree(&[(SPDX_SBOM, &e, e.len() as u64)]),
            &mem_tree(&[(SPDX_SBOM, &a, a.len() as u64)]),
            Rules::Root,
            1 << 20,
        )
        .unwrap();
        assert_eq!(reports[0].status, FileStatus::ExpectedDifference);
    }

    #[test]
    fn sboms_listing_other_packages_fail() {
        let expected = files(&[(SPDX_SBOM, spdx("1", &[("glibc", "2.41"), ("ssh", "9")]))]);
        let actual = files(&[(SPDX_SBOM, spdx("2", &[("glibc", "2.42"), ("ssh", "9")]))]);
        let reports = compare_files(&expected, &actual, Rules::Root);
        assert_eq!(reports[0].status, FileStatus::Mismatch);
        assert!(
            reports[0].detail.contains(
                "only or more often in the rebuilt SBOM: glibc 2.41; in the published SBOM: glibc 2.42"
            ),
            "{}",
            reports[0].detail
        );

        // A package listed once more counts.
        let actual = files(&[(
            SPDX_SBOM,
            spdx("2", &[("glibc", "2.41"), ("ssh", "9"), ("ssh", "9")]),
        )]);
        let reports = compare_files(&expected, &actual, Rules::Root);
        assert_eq!(reports[0].status, FileStatus::Mismatch);

        // So do files that are not SBOMs, or SBOMs of another format.
        let actual = files(&[(SPDX_SBOM, b"not json".to_vec())]);
        let reports = compare_files(&expected, &actual, Rules::Root);
        assert_eq!(reports[0].status, FileStatus::Mismatch);
        let actual = files(&[(
            SPDX_SBOM,
            br#"{"bomFormat":"CycloneDX","components":[]}"#.to_vec(),
        )]);
        let reports = compare_files(&expected, &actual, Rules::Root);
        assert_eq!(reports[0].status, FileStatus::Mismatch);
        assert!(
            reports[0]
                .detail
                .contains("SPDX SBOM rebuilt but CycloneDX SBOM published"),
            "{}",
            reports[0].detail
        );

        // Only ROOT-A has SBOMs that may differ.
        let expected = files(&[(SPDX_SBOM, spdx("1", &[("glibc", "2.41")]))]);
        let actual = files(&[(SPDX_SBOM, spdx("2", &[("glibc", "2.41")]))]);
        let reports = compare_files(&expected, &actual, Rules::Exact);
        assert_eq!(reports[0].status, FileStatus::Mismatch);
    }

    #[test]
    fn only_key_sections_are_expected_pe_differences() {
        let names = |n: &[&str]| {
            Ok(n.iter()
                .map(|s| SectionDifference::new(&(s.to_string(), 1), Some(b"1"), Some(b"2"), true))
                .collect())
        };
        let (status, detail) = describe_pe_difference(&names(&[".vendor_cert"]));
        assert_eq!(status, FileStatus::ExpectedDifference);
        assert_eq!(
            detail,
            "differs only in sections holding embedded keys (.vendor_cert)"
        );

        let (status, _) = describe_pe_difference(&names(&[".pubkey"]));
        assert_eq!(status, FileStatus::ExpectedDifference);

        let (status, detail) = describe_pe_difference(&names(&[".text", ".vendor_cert"]));
        assert_eq!(status, FileStatus::Mismatch);
        assert!(detail.contains(".text, .vendor_cert"), "{detail}");

        let (status, detail) = describe_pe_difference(&names(&[]));
        assert_eq!(status, FileStatus::Mismatch);
        assert!(detail.contains("headers"), "{detail}");

        let (status, _) =
            describe_pe_difference(&Err(snafu::FromString::without_source("bad".to_string())));

        // Key sections must be in both binaries.
        let added = SectionDifference::new(&(".pubkey".to_string(), 1), None, Some(b"2"), true);
        assert_eq!(added.expected, None);
        assert_eq!(status, FileStatus::Mismatch);
    }

    /// A UKI's kernel command line with the given verity root hash and salt.
    pub fn uki_cmdline(root: &str, salt: &str, extra: &str) -> Vec<u8> {
        format!(
            "console=ttyS0 root=/dev/dm-0 rootwait ro{extra} dm-mod.create=\"root,,,ro,0 2400 \
             verity 1 PARTUUID=0b5e4d1a-0000-4000-8000-000000000001/PARTNROFF=2 \
             PARTUUID=0b5e4d1a-0000-4000-8000-000000000001/PARTNROFF=3 4096 4096 300 1 sha256 \
             {root} {salt} 2 restart_on_corruption ignore_zero_blocks\" -- \
             systemd.log_target=journal-or-kmsg"
        )
        .into_bytes()
    }

    /// A minimal UKI with `.linux` and `.cmdline` sections.
    pub fn uki(kernel: &[u8], cmdline: &[u8]) -> Vec<u8> {
        assert!(kernel.len() <= 0x400 && cmdline.len() <= 0x400);
        let mut pe = vec![0u8; 0xa00];
        let put32 = |pe: &mut Vec<u8>, at: usize, v: u32| {
            pe[at..at + 4].copy_from_slice(&v.to_le_bytes());
        };
        pe[0..2].copy_from_slice(b"MZ");
        put32(&mut pe, 0x3c, 0x40); // PE header offset
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        pe[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine: x86-64
        pe[0x46..0x48].copy_from_slice(&2u16.to_le_bytes()); // NumberOfSections
        pe[0x54..0x56].copy_from_slice(&0xf0u16.to_le_bytes()); // SizeOfOptionalHeader
        pe[0x56..0x58].copy_from_slice(&0x22u16.to_le_bytes()); // Characteristics
        pe[0x58..0x5a].copy_from_slice(&0x20bu16.to_le_bytes()); // Magic: PE32+
        put32(&mut pe, 0x78, 0x1000); // SectionAlignment
        put32(&mut pe, 0x7c, 0x200); // FileAlignment
        put32(&mut pe, 0x90, 0x4000); // SizeOfImage
        put32(&mut pe, 0x94, 0x200); // SizeOfHeaders
        pe[0x9c..0x9e].copy_from_slice(&10u16.to_le_bytes()); // Subsystem: EFI application
        put32(&mut pe, 0xc4, 16); // NumberOfRvaAndSizes

        // 0x400 bytes in the file and a page in memory per section.
        for (i, (name, data)) in [(b".linux\0\0", kernel), (b".cmdline", cmdline)]
            .into_iter()
            .enumerate()
        {
            let header = 0x148 + i * 0x28;
            let raw_offset = 0x200 + i as u32 * 0x400;
            pe[header..header + 8].copy_from_slice(name);
            put32(&mut pe, header + 8, data.len() as u32); // VirtualSize
            put32(&mut pe, header + 12, 0x1000 * (i as u32 + 1)); // VirtualAddress
            put32(&mut pe, header + 16, 0x400); // SizeOfRawData
            put32(&mut pe, header + 20, raw_offset); // PointerToRawData
            put32(&mut pe, header + 36, 0x40000040); // Characteristics: initialized, readable
            let offset = raw_offset as usize;
            pe[offset..offset + data.len()].copy_from_slice(data);
        }
        pe
    }

    #[test]
    fn uki_may_differ_only_in_the_verity_digests_of_its_command_line() {
        let (root, other_root) = ("a".repeat(64), "b".repeat(64));
        let rebuilt = uki(b"kernel", &uki_cmdline(&root, "00", ""));
        let compare = |published: &[u8]| compare_pe(&rebuilt, published, true);
        let resalted = uki(b"kernel", &uki_cmdline(&other_root, "11", ""));

        let (status, detail) = compare(&resalted);
        assert_eq!(status, FileStatus::ExpectedDifference, "{detail}");
        assert!(
            detail.ends_with(
                "differs only in the verity root hash and salt of the kernel command line \
                 (.cmdline)"
            ),
            "{detail}"
        );
        // Only for the UKI whose command line BOOT-CONFIG checks.
        let (status, _) = compare_pe(&rebuilt, &resalted, false);
        assert_eq!(status, FileStatus::Mismatch);

        // Any other difference in the command line or the kernel is a mismatch.
        for published in [
            uki(b"kernel", &uki_cmdline(&other_root, "11", " init=/bin/sh")),
            uki(b"kernal", &uki_cmdline(&other_root, "11", "")),
        ] {
            let (status, detail) = compare(&published);
            assert_eq!(status, FileStatus::Mismatch, "{detail}");
        }
    }

    #[test]
    fn allowed_section_differences_do_not_hide_header_changes() {
        let (root, other_root) = ("a".repeat(64), "b".repeat(64));
        let rebuilt = uki(b"kernel", &uki_cmdline(&root, "00", ""));
        let resalted = uki(b"kernel", &uki_cmdline(&other_root, "11", ""));
        // Make the command line section executable, as if code had been put in it.
        let mut executable = resalted.clone();
        let characteristics = 0x148 + 0x28 + 36;
        executable[characteristics..characteristics + 4]
            .copy_from_slice(&0x60000020u32.to_le_bytes());
        // Move the entry point.
        let mut entry = resalted.clone();
        entry[0x58 + 16..0x58 + 20].copy_from_slice(&0x2000u32.to_le_bytes());
        for published in [executable, entry] {
            let (status, detail) = compare_pe(&rebuilt, &published, true);
            assert_eq!(status, FileStatus::Mismatch, "{detail}");
            assert!(
                detail.ends_with("but its headers or layout differ too"),
                "{detail}"
            );
        }

        // A signature appended to only one of them is not a header change.
        let mut signed = resalted.clone();
        let certificates = 0x58 + 112 + 4 * 8;
        let len = signed.len() as u32;
        signed[certificates..certificates + 4].copy_from_slice(&len.to_le_bytes());
        signed[certificates + 4..certificates + 8].copy_from_slice(&16u32.to_le_bytes());
        signed.extend([7u8; 16]);
        let (status, detail) = compare_pe(&rebuilt, &signed, true);
        assert_eq!(status, FileStatus::ExpectedDifference, "{detail}");
    }

    /// An HMAC file as rpm2img writes it for `target`, holding `data`.
    pub fn hmac_file(target: &str, data: &[u8]) -> Vec<u8> {
        format!("{}  {target}\n", hex::encode(hmac_sha512(HMAC_KEY, data))).into_bytes()
    }

    #[test]
    fn computes_hmac_sha512() {
        // RFC 4231, test case 2, and a key longer than the block size (test case 6).
        assert_eq!(
            hex::encode(hmac_sha512(b"Jefe", b"what do ya want for nothing?")),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
        assert_eq!(
            hex::encode(hmac_sha512(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
             6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        );
    }

    #[test]
    fn hmacs_must_match_the_published_file() {
        let vmlinuz = |v: &[u8]| ("/vmlinuz", v.to_vec());
        let hmac = |target: &str, v: &[u8]| ("/.vmlinuz.hmac", hmac_file(target, v));
        let rebuilt = files(&[vmlinuz(b"MZone"), hmac("vmlinuz", b"MZone")]);
        let status = |published: &Files| {
            let reports = compare_files(&rebuilt, published, Rules::Boot);
            let r = reports.iter().find(|r| r.path == "/.vmlinuz.hmac");
            let r = r.unwrap_or_else(|| panic!("no HMAC report in {reports:#?}"));
            (r.status, r.detail.clone())
        };

        // Checked against the published kernel, which is compared on its own.
        let (s, detail) = status(&files(&[vmlinuz(b"MZtwo"), hmac("vmlinuz", b"MZtwo")]));
        assert_eq!(s, FileStatus::ExpectedDifference, "{detail}");
        let reports = compare_files(&rebuilt, &rebuilt, Rules::Boot);
        assert!(reports.is_empty(), "{reports:#?}");

        for (published, error) in [
            (
                files(&[vmlinuz(b"MZtwo"), hmac("vmlinuz", b"MZone")]),
                "is not the HMAC of the published /vmlinuz",
            ),
            (
                files(&[vmlinuz(b"MZtwo"), hmac("vmlinux", b"MZtwo")]),
                "covers vmlinux instead of vmlinuz",
            ),
            (
                files(&[("/.vmlinuz.hmac", b"garbage".to_vec())]),
                "not an HMAC of the form",
            ),
            (
                files(&[hmac("vmlinuz", b"MZtwo")]),
                "the published image has no single /vmlinuz",
            ),
        ] {
            let (s, detail) = status(&published);
            assert_eq!(s, FileStatus::Mismatch, "{detail}");
            assert!(detail.starts_with(error), "{detail}");
        }
    }

    #[test]
    fn signing_artifacts_must_be_in_both_images() {
        let rebuilt = files(&[("/EFI/BOOT/db.crt", b"cert1".to_vec())]);
        let reports = compare_files(
            &rebuilt,
            &files(&[("/EFI/BOOT/db.crt", b"cert2".to_vec())]),
            Rules::Boot,
        );
        assert_eq!(reports[0].status, FileStatus::ExpectedDifference);
        let published = files(&[
            ("/EFI/BOOT/db.crt", b"cert2".to_vec()),
            ("/EFI/BOOT/extra.auth", b"x".to_vec()),
        ]);
        let reports = compare_files(&rebuilt, &published, Rules::Boot);
        let extra = reports
            .iter()
            .find(|r| r.path == "/EFI/BOOT/extra.auth")
            .unwrap();
        assert_eq!(extra.status, FileStatus::Mismatch);
        let reports = compare_files(&rebuilt, &Files::new(), Rules::Boot);
        assert_eq!(reports[0].status, FileStatus::Mismatch);

        // Only grub.cfg may differ in its verity digests.
        let table =
            |root: &str| format!("verity 1 a b 4096 4096 1 1 sha256 {root} 00").into_bytes();
        let reports = compare_files(
            &files(&[("/grub/other.cfg", table(&"a".repeat(64)))]),
            &files(&[("/grub/other.cfg", table(&"b".repeat(64)))]),
            Rules::Boot,
        );
        assert_eq!(reports[0].status, FileStatus::Mismatch);
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
        // The size alone fails it.
        let actual = mem_tree(&[("/big", b"", 1 << 40)]);
        let reports = compare_trees(&expected, &actual, Rules::Root, 1 << 20).unwrap();
        assert_eq!(reports[0].status, FileStatus::Mismatch);
        assert!(reports[0].detail.contains("not read"), "{reports:?}");
    }
}
