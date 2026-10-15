//! dm-verity (format 1) hash tree computation, matching `veritysetup format`.
//!
//! Bottlerocket formats HASH-A with a random salt and UUID, so a rebuilt image
//! never has a byte-identical HASH-A. Recomputing the tree over the rebuilt
//! ROOT-A with the published image's salt shows whether the published image's
//! verity metadata (and therefore its boot-time integrity check) is bound to
//! the rootfs that was built from source.

use crate::error::Result;
use regex::bytes::Regex;
use sha2::{Digest, Sha256};
use snafu::{ensure_whatever, OptionExt, ResultExt};
use std::io::Read;
use std::sync::LazyLock;

/// Size of the on-disk verity superblock.
pub const SUPERBLOCK_SIZE: usize = 512;
const SIGNATURE: &[u8; 8] = b"verity\0\0";
const DIGEST_SIZE: usize = 32;
const MAX_SALT_SIZE: usize = 256;
/// dm-verity only accepts block sizes up to the page size, which is at most 64 KiB.
const MAX_BLOCK_SIZE: usize = 65536;

/// Matches the verity target in a device-mapper table, as found in
/// `dm-mod.create=` on the kernel command line.
static TABLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"verity (?P<version>\d+) (?P<data_dev>\S+) (?P<hash_dev>\S+) (?P<dbs>\d+) (?P<hbs>\d+) (?P<blocks>\d+) (?P<start>\d+) (?P<alg>[a-z0-9]+) (?P<root>[0-9a-fA-F]+) (?P<salt>[0-9a-fA-F]+|-)",
    )
    .expect("valid regex")
});

/// Parameters of a dm-verity device as given in its device-mapper table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerityTable {
    pub version: u32,
    pub data_device: String,
    pub hash_device: String,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_blocks: u64,
    pub hash_start_block: u64,
    pub algorithm: String,
    pub root_hash: Vec<u8>,
    pub salt: Vec<u8>,
}

impl VerityTable {
    /// Parse the verity table in `text`, which must contain exactly one.
    pub fn find_unique(text: &[u8]) -> Result<Self> {
        let mut tables = TABLE_RE.captures_iter(text);
        let caps = tables.next().whatever_context("no dm-verity table found")?;
        ensure_whatever!(
            tables.next().is_none(),
            "more than one dm-verity table found"
        );
        let s = |name: &str| String::from_utf8_lossy(&caps[name]).into_owned();
        (|| {
            let salt = match s("salt").as_str() {
                "-" => Vec::new(),
                hex_salt => hex::decode(hex_salt).whatever_context("invalid verity salt")?,
            };
            Ok(Self {
                version: s("version")
                    .parse()
                    .whatever_context("invalid verity version")?,
                data_device: s("data_dev"),
                hash_device: s("hash_dev"),
                data_block_size: s("dbs")
                    .parse()
                    .whatever_context("invalid data block size")?,
                hash_block_size: s("hbs")
                    .parse()
                    .whatever_context("invalid hash block size")?,
                data_blocks: s("blocks")
                    .parse()
                    .whatever_context("invalid data blocks")?,
                hash_start_block: s("start").parse().whatever_context("invalid hash start")?,
                algorithm: s("alg"),
                root_hash: hex::decode(s("root")).whatever_context("invalid verity root hash")?,
                salt,
            })
        })()
    }

    fn validate(&self) -> Result<()> {
        ensure_whatever!(
            self.version == 1,
            "unsupported verity format {}",
            self.version
        );
        ensure_whatever!(
            self.algorithm == "sha256",
            "unsupported verity hash algorithm '{}'",
            self.algorithm
        );
        for size in [self.data_block_size, self.hash_block_size] {
            ensure_whatever!(
                size.is_power_of_two()
                    && (SUPERBLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&(size as usize)),
                "unsupported verity block size {size}"
            );
        }
        ensure_whatever!(self.salt.len() <= MAX_SALT_SIZE, "verity salt is too long");
        ensure_whatever!(self.data_blocks >= 2, "verity device is too small");
        Ok(())
    }

    /// Describe the table for the log, with the root hash and salt in hex.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "version": self.version,
            "data_device": self.data_device,
            "hash_device": self.hash_device,
            "data_block_size": self.data_block_size,
            "hash_block_size": self.hash_block_size,
            "data_blocks": self.data_blocks,
            "hash_start_block": self.hash_start_block,
            "algorithm": self.algorithm,
            "root_hash": hex::encode(&self.root_hash),
            "salt": hex::encode(&self.salt),
        })
    }

    /// The size of the hash device this table describes: the hash start
    /// offset plus every level of the hash tree.
    ///
    /// The table comes from the published image, so this lets callers check
    /// it against the size of HASH-A before computing or allocating the tree.
    pub fn hash_device_len(&self) -> Result<u64> {
        self.validate()?;
        let hbs = u64::from(self.hash_block_size);
        let per_block = hbs / DIGEST_SIZE as u64;
        let mut count = self.data_blocks;
        let mut blocks = 0u64;
        loop {
            let level = count.div_ceil(per_block);
            blocks += level;
            if level == 1 {
                break;
            }
            count = level;
        }
        blocks
            .checked_mul(hbs)
            .and_then(|tree| self.hash_start_block.checked_mul(hbs)?.checked_add(tree))
            .whatever_context("verity hash device size overflows")
    }
}

/// A computed verity hash tree.
#[derive(Debug)]
pub struct VerityTree {
    pub root_hash: [u8; DIGEST_SIZE],
    /// Hash blocks in on-disk order (top level first), starting at the hash start block.
    pub hash_area: Vec<u8>,
}

fn salted_digest(salt: &[u8], data: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute the verity hash tree over the first `table.data_blocks` blocks of `data`.
pub fn compute_tree<R: Read>(data: &mut R, table: &VerityTable) -> Result<VerityTree> {
    table.validate()?;
    let hbs = table.hash_block_size as usize;
    let per_block = hbs / DIGEST_SIZE;
    ensure_whatever!(
        per_block.is_power_of_two(),
        "hash block size must hold a power-of-two number of digests"
    );

    let digests_len = usize::try_from(table.data_blocks)
        .ok()
        .and_then(|n| n.checked_mul(DIGEST_SIZE))
        .whatever_context("verity data block count overflows")?;
    let mut block = vec![0u8; table.data_block_size as usize];
    let mut digests = Vec::with_capacity(digests_len);
    for i in 0..table.data_blocks {
        data.read_exact(&mut block)
            .whatever_context(format!("failed to read verity data block {i}"))?;
        digests.extend_from_slice(&salted_digest(&table.salt, &block));
    }

    // Build levels bottom-up; each level packs the digests of the level below
    // into zero-padded hash blocks, until a single block remains.
    let mut levels: Vec<Vec<u8>> = Vec::new();
    loop {
        let count = digests.len() / DIGEST_SIZE;
        let nblocks = count.div_ceil(per_block);
        let mut level = vec![0u8; nblocks * hbs];
        for (i, digest) in digests.chunks(DIGEST_SIZE).enumerate() {
            let offset = (i / per_block) * hbs + (i % per_block) * DIGEST_SIZE;
            level[offset..offset + DIGEST_SIZE].copy_from_slice(digest);
        }
        digests = level
            .chunks(hbs)
            .flat_map(|b| salted_digest(&table.salt, b))
            .collect();
        levels.push(level);
        if nblocks == 1 {
            break;
        }
    }

    let root_hash: [u8; DIGEST_SIZE] = digests
        .as_slice()
        .try_into()
        .whatever_context("verity tree did not converge to a single root")?;
    let hash_area = levels.into_iter().rev().flatten().collect();
    Ok(VerityTree {
        root_hash,
        hash_area,
    })
}

/// Return the UUID stored in a verity superblock, if `data` begins with one.
pub fn superblock_uuid(data: &[u8]) -> Option<[u8; 16]> {
    if data.len() < SUPERBLOCK_SIZE || &data[..8] != SIGNATURE {
        return None;
    }
    data[16..32].try_into().ok()
}

/// Build the 512-byte superblock `veritysetup format` writes for `table`.
pub fn build_superblock(table: &VerityTable, uuid: [u8; 16]) -> [u8; SUPERBLOCK_SIZE] {
    let mut sb = [0u8; SUPERBLOCK_SIZE];
    sb[..8].copy_from_slice(SIGNATURE);
    sb[8..12].copy_from_slice(&1u32.to_le_bytes()); // superblock version
    sb[12..16].copy_from_slice(&table.version.to_le_bytes()); // hash type
    sb[16..32].copy_from_slice(&uuid);
    let alg = table.algorithm.as_bytes();
    let alg_len = alg.len().min(32);
    sb[32..32 + alg_len].copy_from_slice(&alg[..alg_len]);
    sb[64..68].copy_from_slice(&table.data_block_size.to_le_bytes());
    sb[68..72].copy_from_slice(&table.hash_block_size.to_le_bytes());
    sb[72..80].copy_from_slice(&table.data_blocks.to_le_bytes());
    sb[80..82].copy_from_slice(&(table.salt.len() as u16).to_le_bytes());
    sb[88..88 + table.salt.len()].copy_from_slice(&table.salt);
    sb
}

/// Build the content `veritysetup format` writes to the hash device: the
/// superblock (when the hash area starts after block 0) followed by the tree.
/// Everything after the returned bytes is zero on a freshly formatted device.
///
/// `device_len` is the size of the hash device; the table comes from the
/// published image, so its hash start is checked against it before allocating.
pub fn build_hash_device(
    table: &VerityTable,
    tree: &VerityTree,
    uuid: Option<[u8; 16]>,
    device_len: u64,
) -> Result<Vec<u8>> {
    table.validate()?;
    let start = table
        .hash_start_block
        .checked_mul(u64::from(table.hash_block_size))
        .whatever_context("verity hash start overflows")?;
    let end = start
        .checked_add(tree.hash_area.len() as u64)
        .whatever_context("verity hash device size overflows")?;
    ensure_whatever!(
        end <= device_len,
        "verity hash tree ({} bytes at byte {start}) does not fit in the {device_len}-byte hash device",
        tree.hash_area.len()
    );
    let mut out = vec![0u8; start as usize];
    if start > 0 {
        let uuid = uuid.whatever_context("verity hash device has no superblock")?;
        out[..SUPERBLOCK_SIZE].copy_from_slice(&build_superblock(table, uuid));
    }
    out.extend_from_slice(&tree.hash_area);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Data for the fixture: block `i` is sha256("i") repeated to fill 4 KiB.
    fn fixture_data(blocks: usize) -> Vec<u8> {
        (0..blocks)
            .flat_map(|i| {
                let d: [u8; 32] = Sha256::digest(i.to_string().as_bytes()).into();
                d.repeat(128)
            })
            .collect()
    }

    // Produced by:
    //   veritysetup format --format 1 --hash sha256 --data-block-size 4096 \
    //     --hash-block-size 4096 --salt 00112233445566778899aabbccddeeff \
    //     --uuid 01234567-89ab-cdef-0123-456789abcdef data.img hash.img
    // where data.img is `fixture_data(300)` and hash.img was pre-truncated to 64 KiB.
    const FIXTURE_ROOT: &str = "6bd753646492b7e0be9495e309313af09f67e10fffb415ac588c0feb1712e9e2";
    const FIXTURE_HASH_IMG_SHA256: &str =
        "155e6a62582f3c9aa15347fdf7f3a41968ec19d96e678df5c0c4453a1b003848";
    const FIXTURE_UUID: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];

    fn fixture_table() -> VerityTable {
        let cmdline = format!(
            "root=/dev/dm-0 dm-mod.create=\"root,,,ro,0 2400 verity 1 PARTUUID=$boot_uuid/PARTNROFF=1 \
             PARTUUID=$boot_uuid/PARTNROFF=2 4096 4096 300 1 sha256 {FIXTURE_ROOT} \
             00112233445566778899aabbccddeeff 2 restart_on_corruption ignore_zero_blocks\" --"
        );
        VerityTable::find_unique(cmdline.as_bytes()).unwrap()
    }

    #[test]
    fn parses_table() {
        let table = fixture_table();
        assert_eq!(table.version, 1);
        assert_eq!(table.data_device, "PARTUUID=$boot_uuid/PARTNROFF=1");
        assert_eq!(table.hash_device, "PARTUUID=$boot_uuid/PARTNROFF=2");
        assert_eq!(table.data_block_size, 4096);
        assert_eq!(table.hash_block_size, 4096);
        assert_eq!(table.data_blocks, 300);
        assert_eq!(table.hash_start_block, 1);
        assert_eq!(table.algorithm, "sha256");
        assert_eq!(hex::encode(&table.root_hash), FIXTURE_ROOT);
        assert_eq!(table.salt.len(), 16);
    }

    #[test]
    fn parses_unsalted_table() {
        let text = format!("verity 1 a b 4096 4096 10 1 sha256 {FIXTURE_ROOT} -");
        let table = VerityTable::find_unique(text.as_bytes()).unwrap();
        assert!(table.salt.is_empty());
    }

    #[test]
    fn requires_exactly_one_table() {
        assert!(VerityTable::find_unique(b"root=/dev/xvda1 ro").is_err());
        let table = format!("verity 1 a b 4096 4096 10 1 sha256 {FIXTURE_ROOT} -");
        let decoy = format!("{table} # {table}");
        assert!(VerityTable::find_unique(decoy.as_bytes()).is_err());
    }

    #[test]
    fn rejects_huge_block_sizes() {
        let mut table = fixture_table();
        table.hash_block_size = 1 << 31;
        assert!(table.hash_device_len().is_err());
        assert!(compute_tree(&mut Cursor::new(fixture_data(300)), &table).is_err());
        table.hash_block_size = 4096;
        table.data_block_size = 1 << 17;
        assert!(table.hash_device_len().is_err());
    }

    #[test]
    fn computes_hash_device_len() {
        let mut table = fixture_table();
        // Superblock block, 3 level-0 blocks and 1 level-1 block.
        assert_eq!(table.hash_device_len().unwrap(), 5 * 4096);
        let tree = compute_tree(&mut Cursor::new(fixture_data(300)), &table).unwrap();
        let device = build_hash_device(&table, &tree, Some(FIXTURE_UUID), 64 * 1024).unwrap();
        assert_eq!(device.len() as u64, table.hash_device_len().unwrap());
        table.hash_start_block = u64::MAX / 4096;
        assert!(table.hash_device_len().is_err());
    }

    #[test]
    fn matches_veritysetup_fixture() {
        let table = fixture_table();
        let tree = compute_tree(&mut Cursor::new(fixture_data(300)), &table).unwrap();
        assert_eq!(hex::encode(tree.root_hash), FIXTURE_ROOT);
        // 3 level-0 blocks + 1 level-1 block
        assert_eq!(tree.hash_area.len(), 4 * 4096);

        let mut device = build_hash_device(&table, &tree, Some(FIXTURE_UUID), 64 * 1024).unwrap();
        assert_eq!(superblock_uuid(&device), Some(FIXTURE_UUID));
        device.resize(64 * 1024, 0);
        assert_eq!(
            hex::encode(Sha256::digest(&device)),
            FIXTURE_HASH_IMG_SHA256
        );
    }

    #[test]
    fn rejects_hash_start_beyond_device() {
        let mut table = fixture_table();
        let tree = compute_tree(&mut Cursor::new(fixture_data(300)), &table).unwrap();
        // A hash start of 1 TiB must be rejected before anything is allocated.
        table.hash_start_block = 1 << 28;
        assert!(build_hash_device(&table, &tree, Some(FIXTURE_UUID), 64 * 1024).is_err());
        table.hash_start_block = u64::MAX;
        assert!(build_hash_device(&table, &tree, Some(FIXTURE_UUID), 64 * 1024).is_err());
        // The tree must fit after the hash start, not just the start itself.
        table.hash_start_block = 15;
        assert!(build_hash_device(&table, &tree, Some(FIXTURE_UUID), 64 * 1024).is_err());
    }

    #[test]
    fn detects_changed_data() {
        let table = fixture_table();
        let mut data = fixture_data(300);
        data[4096 * 150] ^= 1;
        let tree = compute_tree(&mut Cursor::new(data), &table).unwrap();
        assert_ne!(hex::encode(tree.root_hash), FIXTURE_ROOT);
    }

    #[test]
    fn single_level_tree() {
        let mut table = fixture_table();
        table.data_blocks = 128;
        let tree = compute_tree(&mut Cursor::new(fixture_data(128)), &table).unwrap();
        assert_eq!(tree.hash_area.len(), 4096);
    }

    #[test]
    fn short_data_errors() {
        let table = fixture_table();
        assert!(compute_tree(&mut Cursor::new(fixture_data(10)), &table).is_err());
    }
}
