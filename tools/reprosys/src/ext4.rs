//! Reading ext4 root filesystems.
//!
//! File types, permissions, ownership, symlink targets and contents are read
//! with ext4-view. It exposes neither extended attributes, device numbers nor
//! inode numbers, so the directory tree is also walked here, from the on-disk
//! format, to read the extended attributes and device number of each entry's
//! inode. Both walks must find the same entries. Layouts this walk does not
//! handle (meta_bg, inline directories, block-mapped directories, attribute
//! values stored in inodes) are reported as errors rather than skipped.

use crate::error::Result;
use crate::fsfiles::{self, display, Entry, FileTree, FsPath, Kind, Xattrs};
use ext4_view::{Ext4, Ext4Read, Metadata};
use snafu::{ensure_whatever, OptionExt, ResultExt};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;

const SUPERBLOCK_OFFSET: u64 = 1024;
const MAGIC: u16 = 0xef53;
const ROOT_INODE: u32 = 2;
const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_META_BG: u32 = 0x10;
const INCOMPAT_64BIT: u32 = 0x80;
const EXTENTS_FL: u32 = 0x8_0000;
const INLINE_DATA_FL: u32 = 0x1000_0000;
const EXTENT_MAGIC: u16 = 0xf30a;
const MAX_EXTENT_DEPTH: u16 = 5;
/// Bounds the extent tree nodes read for one inode, since a corrupt tree can
/// point many index entries at the same node.
const MAX_EXTENT_NODES: usize = 1 << 16;
/// Extents longer than this are uninitialized, and read as zeros.
const MAX_INIT_EXTENT_LEN: u64 = 32768;
const XATTR_MAGIC: u32 = 0xea02_0000;
const XATTR_ENTRY_SIZE: usize = 16;
/// Size of the header of an extended attribute block.
const XATTR_BLOCK_HEADER_SIZE: usize = 32;
const S_IFMT: u16 = 0xf000;
const S_IFDIR: u16 = 0x4000;
const S_IFCHR: u16 = 0x2000;
const S_IFBLK: u16 = 0x6000;

fn u16_at(b: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(b[offset..offset + 2].try_into().expect("2 bytes"))
}

fn u32_at(b: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(b[offset..offset + 4].try_into().expect("4 bytes"))
}

/// Reads a partition of a disk image without loading it into memory.
struct PartitionReader {
    file: File,
    offset: u64,
    len: u64,
}

impl PartitionReader {
    fn read_at(&self, dst: &mut [u8], pos: u64) -> std::io::Result<()> {
        pos.checked_add(dst.len() as u64)
            .filter(|end| *end <= self.len)
            .ok_or_else(|| std::io::Error::other("read beyond the end of the partition"))?;
        self.file.read_exact_at(dst, self.offset + pos)
    }
}

impl Ext4Read for PartitionReader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.read_at(dst, start_byte)?)
    }
}

/// A run of blocks in an inode's extent tree.
struct Extent {
    logical: u64,
    start: u64,
    len: u64,
    initialized: bool,
}

/// What the on-disk walk reads about an entry, which ext4-view does not expose.
struct RawEntry {
    xattrs: Xattrs,
    device: Option<(u32, u32)>,
}

/// The major and minor number of a character or block device inode.
fn inode_device(inode: &[u8]) -> Option<(u32, u32)> {
    if !matches!(u16_at(inode, 0) & S_IFMT, S_IFCHR | S_IFBLK) {
        return None;
    }
    // As in the kernel: the old 8:8 encoding in i_block[0] if it is set,
    // otherwise the new encoding in i_block[1].
    let old = u32_at(inode, 0x28);
    Some(if old != 0 {
        ((old >> 8) & 0xff, old & 0xff)
    } else {
        fsfiles::decode_device(u32_at(inode, 0x2c))
    })
}

/// The parts of the on-disk format needed to walk directories and read
/// extended attributes.
struct RawExt4 {
    reader: PartitionReader,
    block_size: u64,
    inodes_count: u32,
    inodes_per_group: u32,
    inode_size: u64,
    desc_size: u64,
    desc_table: u64,
    filetype: bool,
    is_64bit: bool,
}

impl RawExt4 {
    fn open(reader: PartitionReader) -> Result<Self> {
        let mut sb = [0u8; 1024];
        reader
            .read_at(&mut sb, SUPERBLOCK_OFFSET)
            .whatever_context("failed to read ext4 superblock")?;
        ensure_whatever!(u16_at(&sb, 0x38) == MAGIC, "not an ext4 filesystem");
        let log_block_size = u32_at(&sb, 0x18);
        ensure_whatever!(
            log_block_size <= 6,
            "unsupported ext4 block size 2^{}",
            log_block_size + 10
        );
        let block_size = 1024u64 << log_block_size;
        let incompat = u32_at(&sb, 0x60);
        ensure_whatever!(
            incompat & INCOMPAT_META_BG == 0,
            "ext4 filesystems with meta_bg are not supported"
        );
        let inode_size = match u32_at(&sb, 0x4c) {
            0 => 128,
            _ => u64::from(u16_at(&sb, 0x58)),
        };
        ensure_whatever!(
            inode_size >= 128 && inode_size.is_power_of_two() && inode_size <= block_size,
            "invalid ext4 inode size {inode_size}"
        );
        let is_64bit = incompat & INCOMPAT_64BIT != 0;
        let desc_size = if is_64bit {
            u64::from(u16_at(&sb, 0xfe))
        } else {
            32
        };
        ensure_whatever!(
            desc_size >= 32 && desc_size.is_power_of_two() && desc_size <= block_size,
            "invalid ext4 group descriptor size {desc_size}"
        );
        let inodes_per_group = u32_at(&sb, 0x28);
        ensure_whatever!(inodes_per_group > 0, "ext4 has no inodes per group");
        let first_data_block = u64::from(u32_at(&sb, 0x14));
        Ok(Self {
            reader,
            block_size,
            inodes_count: u32_at(&sb, 0),
            inodes_per_group,
            inode_size,
            desc_size,
            desc_table: (first_data_block + 1) * block_size,
            filetype: incompat & INCOMPAT_FILETYPE != 0,
            is_64bit,
        })
    }

    fn read_block(&self, block: u64) -> Result<Vec<u8>> {
        let pos = block
            .checked_mul(self.block_size)
            .whatever_context("ext4 block number overflows")?;
        let mut out = vec![0u8; self.block_size as usize];
        self.reader
            .read_at(&mut out, pos)
            .whatever_context(format!("failed to read ext4 block {block}"))?;
        Ok(out)
    }

    fn inode(&self, ino: u32) -> Result<Vec<u8>> {
        ensure_whatever!(
            (1..=self.inodes_count).contains(&ino),
            "invalid inode number {ino}"
        );
        let index = u64::from(ino - 1);
        let group = index / u64::from(self.inodes_per_group);
        let mut desc = vec![0u8; self.desc_size as usize];
        self.reader
            .read_at(&mut desc, self.desc_table + group * self.desc_size)
            .whatever_context(format!(
                "failed to read the group descriptor of inode {ino}"
            ))?;
        let mut table = u64::from(u32_at(&desc, 0x8));
        if self.desc_size >= 64 {
            table |= u64::from(u32_at(&desc, 0x28)) << 32;
        }
        let pos = table
            .checked_mul(self.block_size)
            .and_then(|t| t.checked_add(index % u64::from(self.inodes_per_group) * self.inode_size))
            .whatever_context(format!("location of inode {ino} overflows"))?;
        let mut inode = vec![0u8; self.inode_size as usize];
        self.reader
            .read_at(&mut inode, pos)
            .whatever_context(format!("failed to read inode {ino}"))?;
        Ok(inode)
    }

    fn extents(&self, inode: &[u8]) -> Result<Vec<Extent>> {
        ensure_whatever!(
            u32_at(inode, 0x20) & EXTENTS_FL != 0,
            "block-mapped (non-extent) inodes are not supported"
        );
        let mut out = Vec::new();
        let mut nodes = 0;
        self.extent_node(&inode[0x28..0x28 + 60], None, &mut nodes, &mut out)?;
        Ok(out)
    }

    fn extent_node(
        &self,
        node: &[u8],
        parent_depth: Option<u16>,
        nodes: &mut usize,
        out: &mut Vec<Extent>,
    ) -> Result<()> {
        *nodes += 1;
        ensure_whatever!(*nodes <= MAX_EXTENT_NODES, "ext4 extent tree is too large");
        ensure_whatever!(
            u16_at(node, 0) == EXTENT_MAGIC,
            "corrupt ext4 extent header"
        );
        let entries = usize::from(u16_at(node, 2));
        let depth = u16_at(node, 6);
        ensure_whatever!(
            depth <= MAX_EXTENT_DEPTH && parent_depth.is_none_or(|d| depth + 1 == d),
            "corrupt ext4 extent tree depth"
        );
        ensure_whatever!(
            12 + entries * 12 <= node.len(),
            "corrupt ext4 extent entry count"
        );
        for entry in node[12..12 + entries * 12].as_chunks::<12>().0 {
            if depth == 0 {
                let len = u64::from(u16_at(entry, 4));
                let initialized = len <= MAX_INIT_EXTENT_LEN;
                out.push(Extent {
                    logical: u64::from(u32_at(entry, 0)),
                    start: u64::from(u16_at(entry, 6)) << 32 | u64::from(u32_at(entry, 8)),
                    len: if initialized {
                        len
                    } else {
                        len - MAX_INIT_EXTENT_LEN
                    },
                    initialized,
                });
            } else {
                let child = u64::from(u16_at(entry, 8)) << 32 | u64::from(u32_at(entry, 4));
                self.extent_node(&self.read_block(child)?, Some(depth), nodes, out)?;
            }
        }
        Ok(())
    }

    /// The names and inode numbers in a directory, without `.` and `..`.
    fn dir_entries(&self, inode: &[u8]) -> Result<Vec<(Vec<u8>, u32)>> {
        ensure_whatever!(
            u32_at(inode, 0x20) & INLINE_DATA_FL == 0,
            "inline directories are not supported"
        );
        let size = u64::from(u32_at(inode, 0x4)) | u64::from(u32_at(inode, 0x6c)) << 32;
        let blocks = size.div_ceil(self.block_size);
        // Bound the work a corrupt size or overlapping extents can cause.
        ensure_whatever!(
            blocks <= self.reader.len / self.block_size,
            "directory is larger than the filesystem"
        );
        let mut read = 0;
        let mut out = Vec::new();
        for extent in self.extents(inode)? {
            if extent.logical >= blocks {
                continue;
            }
            ensure_whatever!(extent.initialized, "directory has an uninitialized extent");
            for i in 0..extent.len.min(blocks - extent.logical) {
                read += 1;
                ensure_whatever!(read <= blocks, "directory extents overlap");
                let block = self.read_block(extent.start + i)?;
                parse_dir_block(&block, self.filetype, &mut out)?;
            }
        }
        Ok(out)
    }

    fn xattrs(&self, inode: &[u8]) -> Result<Xattrs> {
        let mut xattrs = Xattrs::new();
        if self.inode_size > 128 {
            let start = 128 + usize::from(u16_at(inode, 0x80));
            if start + 4 <= inode.len() && u32_at(inode, start) == XATTR_MAGIC {
                // In-inode values are relative to the first entry.
                let entries = &inode[start + 4..];
                parse_xattrs(entries, 0, entries, &mut xattrs)?;
            }
        }
        let mut block = u64::from(u32_at(inode, 0x68));
        if self.is_64bit {
            block |= u64::from(u16_at(inode, 0x76)) << 32;
        }
        if block != 0 {
            let block = self.read_block(block)?;
            ensure_whatever!(
                u32_at(&block, 0) == XATTR_MAGIC && u32_at(&block, 8) == 1,
                "corrupt extended attribute block"
            );
            parse_xattrs(&block, XATTR_BLOCK_HEADER_SIZE, &block, &mut xattrs)?;
        }
        Ok(xattrs)
    }

    /// The extended attributes and device numbers of the root directory and
    /// every entry below it, by path. Fails if a directory is reachable twice.
    fn walk(&self) -> Result<BTreeMap<FsPath, RawEntry>> {
        let mut found = BTreeMap::new();
        let root = self.inode(ROOT_INODE)?;
        found.insert(
            b"/".to_vec(),
            RawEntry {
                xattrs: self.xattrs(&root)?,
                device: None,
            },
        );
        let mut visited = HashSet::from([ROOT_INODE]);
        let mut stack = vec![(b"/".to_vec(), root)];
        while let Some((dir, inode)) = stack.pop() {
            let entries = self
                .dir_entries(&inode)
                .with_whatever_context(|_| format!("failed to read directory {}", display(&dir)))?;
            for (name, ino) in entries {
                let mut path = dir.clone();
                if path != b"/" {
                    path.push(b'/');
                }
                path.extend_from_slice(&name);
                let child = self.inode(ino)?;
                let xattrs = self.xattrs(&child).with_whatever_context(|_| {
                    format!(
                        "failed to read the extended attributes of {}",
                        display(&path)
                    )
                })?;
                let device = inode_device(&child);
                if u16_at(&child, 0) & S_IFMT == S_IFDIR {
                    ensure_whatever!(
                        visited.insert(ino),
                        "directory {} is linked more than once",
                        display(&path)
                    );
                    stack.push((path.clone(), child));
                }
                fsfiles::insert_unique(&mut found, path, RawEntry { xattrs, device })?;
            }
        }
        Ok(found)
    }
}

fn parse_dir_block(block: &[u8], filetype: bool, out: &mut Vec<(Vec<u8>, u32)>) -> Result<()> {
    let mut pos = 0;
    while pos < block.len() {
        ensure_whatever!(pos + 8 <= block.len(), "truncated directory entry");
        let ino = u32_at(block, pos);
        let mut rec_len = usize::from(u16_at(block, pos + 4));
        if block.len() >= 65536 && (rec_len == 0 || rec_len == 65535) {
            rec_len = 65536;
        }
        let name_len = if filetype {
            usize::from(block[pos + 6])
        } else {
            usize::from(u16_at(block, pos + 6))
        };
        ensure_whatever!(
            rec_len >= 8
                && rec_len % 4 == 0
                && pos + rec_len <= block.len()
                && 8 + name_len <= rec_len,
            "corrupt directory entry"
        );
        // Entries with inode 0 are unused space, htree nodes or checksum tails.
        let name = &block[pos + 8..pos + 8 + name_len];
        if ino != 0 && name != b"." && name != b".." {
            out.push((name.to_vec(), ino));
        }
        pos += rec_len;
    }
    Ok(())
}

fn xattr_prefix(index: u8) -> String {
    match index {
        1 => "user.".to_string(),
        2 => "system.posix_acl_access".to_string(),
        3 => "system.posix_acl_default".to_string(),
        4 => "trusted.".to_string(),
        6 => "security.".to_string(),
        7 => "system.".to_string(),
        8 => "system.richacl".to_string(),
        n => format!("<index {n}>."),
    }
}

/// Parse the extended attribute entries starting at `pos` of `entries`, whose
/// values are at offsets within `values`.
fn parse_xattrs(entries: &[u8], mut pos: usize, values: &[u8], out: &mut Xattrs) -> Result<()> {
    loop {
        ensure_whatever!(
            pos + 4 <= entries.len(),
            "unterminated extended attribute list"
        );
        if u32_at(entries, pos) == 0 {
            return Ok(());
        }
        ensure_whatever!(
            pos + XATTR_ENTRY_SIZE <= entries.len(),
            "truncated extended attribute entry"
        );
        let name_len = usize::from(entries[pos]);
        let index = entries[pos + 1];
        let value_offset = usize::from(u16_at(entries, pos + 2));
        let value_inode = u32_at(entries, pos + 4);
        let value_size = u32_at(entries, pos + 8) as usize;
        let name_end = pos + XATTR_ENTRY_SIZE + name_len;
        ensure_whatever!(
            name_end <= entries.len(),
            "truncated extended attribute name"
        );
        ensure_whatever!(
            value_inode == 0,
            "extended attribute values stored in inodes (ea_inode) are not supported"
        );
        let value = values
            .get(value_offset..value_offset + value_size)
            .whatever_context("extended attribute value is out of bounds")?;
        let mut name = xattr_prefix(index).into_bytes();
        name.extend_from_slice(&entries[pos + XATTR_ENTRY_SIZE..name_end]);
        fsfiles::insert_unique(out, name, value.to_vec())?;
        pos = (name_end + 3) & !3;
    }
}

/// An ext4 filesystem in a partition of a disk image.
pub struct Ext4Tree {
    fs: Ext4,
    raw: RawExt4,
}

/// Open the ext4 filesystem in the `len` bytes at `offset` of `file`.
pub fn open(file: &File, offset: u64, len: u64) -> Result<Ext4Tree> {
    let reader = || -> Result<PartitionReader> {
        Ok(PartitionReader {
            file: file
                .try_clone()
                .whatever_context("failed to reopen image")?,
            offset,
            len,
        })
    };
    Ok(Ext4Tree {
        fs: Ext4::load(Box::new(reader()?)).whatever_context("failed to mount ext4 filesystem")?,
        raw: RawExt4::open(reader()?)?,
    })
}

fn ext4_entry(fs: &Ext4, path: &ext4_view::PathBuf, metadata: &Metadata) -> Result<Entry> {
    let file_type = metadata.file_type();
    let kind = if file_type.is_regular_file() {
        Kind::File
    } else if file_type.is_dir() {
        Kind::Directory
    } else if file_type.is_symlink() {
        Kind::Symlink
    } else if file_type.is_char_dev() {
        Kind::CharDevice
    } else if file_type.is_block_dev() {
        Kind::BlockDevice
    } else if file_type.is_fifo() {
        Kind::Fifo
    } else {
        Kind::Socket
    };
    let link = if file_type.is_symlink() {
        let target = fs
            .read_link(path)
            .whatever_context(format!("failed to read symlink {}", path.display()))?;
        Some(target.as_ref().to_vec())
    } else {
        None
    };
    Ok(Entry {
        kind,
        mode: u32::from(metadata.mode()),
        uid: metadata.uid(),
        gid: metadata.gid(),
        link,
        xattrs: Xattrs::new(),
        size: if kind == Kind::File {
            metadata.len()
        } else {
            0
        },
        device: None,
    })
}

/// Reads a file through ext4-view.
struct Ext4File(ext4_view::File);

impl Read for Ext4File {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0
            .read_bytes(buf)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

impl FileTree for Ext4Tree {
    type Handle = ext4_view::PathBuf;

    fn entries(&self) -> Result<BTreeMap<FsPath, (Self::Handle, Entry)>> {
        // Walk the tree from the on-disk format first: it fails on directory
        // cycles, which would otherwise make the walk below loop forever.
        let mut raw = self.raw.walk()?;

        let mut entries = BTreeMap::new();
        let root = ext4_view::PathBuf::new("/");
        let metadata = self
            .fs
            .symlink_metadata(&root)
            .whatever_context("failed to stat /")?;
        let entry = ext4_entry(&self.fs, &root, &metadata)?;
        entries.insert(b"/".to_vec(), (root.clone(), entry));
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            let read_dir = self
                .fs
                .read_dir(&dir)
                .whatever_context(format!("failed to read directory {}", dir.display()))?;
            for entry in read_dir {
                let entry = entry
                    .whatever_context(format!("failed to read directory {}", dir.display()))?;
                let name = entry.file_name();
                if name.as_ref() == b"." || name.as_ref() == b".." {
                    continue;
                }
                let path = entry.path();
                let metadata = entry
                    .metadata()
                    .whatever_context(format!("failed to stat {}", path.display()))?;
                let info = ext4_entry(&self.fs, &path, &metadata)?;
                if metadata.is_dir() {
                    stack.push(path.clone());
                }
                fsfiles::insert_unique(&mut entries, path.as_ref().to_vec(), (path, info))?;
            }
        }

        for (path, (_, entry)) in entries.iter_mut() {
            let RawEntry { xattrs, device } = raw.remove(path).with_whatever_context(|| {
                format!(
                    "{} was not found when reading extended attributes",
                    display(path)
                )
            })?;
            let is_device = matches!(entry.kind, Kind::CharDevice | Kind::BlockDevice);
            ensure_whatever!(
                is_device == device.is_some(),
                "ext4-view and the on-disk format disagree on whether {} is a device",
                display(path)
            );
            entry.xattrs = xattrs;
            entry.device = device;
        }
        if let Some(path) = raw.keys().next() {
            snafu::whatever!(
                "{} was found when reading extended attributes, but not by ext4-view",
                display(path)
            );
        }
        Ok(entries)
    }

    fn open(&self, handle: &Self::Handle) -> Result<Box<dyn Read + '_>> {
        let file = self
            .fs
            .open(handle)
            .whatever_context(format!("failed to open {}", handle.display()))?;
        Ok(Box::new(Ext4File(file)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirent(ino: u32, rec_len: u16, name: &[u8]) -> Vec<u8> {
        let mut out = ino.to_le_bytes().to_vec();
        out.extend(rec_len.to_le_bytes());
        out.push(name.len() as u8);
        out.push(1);
        out.extend(name);
        out.resize(usize::from(rec_len), 0);
        out
    }

    #[test]
    fn reads_device_numbers() {
        let mut inode = vec![0u8; 256];
        assert_eq!(inode_device(&inode), None);
        inode[..2].copy_from_slice(&(S_IFCHR | 0o600).to_le_bytes());
        // The old encoding, used for numbers that fit in 8 bits each.
        inode[0x28..0x2c].copy_from_slice(&0x0501u32.to_le_bytes());
        assert_eq!(inode_device(&inode), Some((5, 1)));
        // The new encoding of 259:300.
        inode[0x28..0x2c].fill(0);
        inode[0x2c..0x30].copy_from_slice(&0x0011_032cu32.to_le_bytes());
        assert_eq!(inode_device(&inode), Some((259, 300)));
    }

    #[test]
    fn parses_directory_blocks() {
        let mut block = dirent(2, 12, b".");
        block.extend(dirent(2, 12, b".."));
        block.extend(dirent(12, 16, b"\xffname"));
        block.extend(dirent(0, 12, b"")); // deleted entry
        block.extend(dirent(13, 1024 - 64, b"last"));
        block.extend(dirent(0, 12, b"")); // checksum tail
        assert_eq!(block.len(), 1024);
        let mut out = Vec::new();
        parse_dir_block(&block, true, &mut out).unwrap();
        assert_eq!(out, [(b"\xffname".to_vec(), 12), (b"last".to_vec(), 13)]);

        // A record running past the block is rejected rather than read.
        let mut bad = dirent(12, 12, b"a");
        bad.extend(dirent(13, 16, b"b"));
        bad.truncate(24);
        assert!(parse_dir_block(&bad, true, &mut Vec::new()).is_err());
        assert!(parse_dir_block(&dirent(12, 4, b""), true, &mut Vec::new()).is_err());
    }

    fn xattr_entry(index: u8, name: &[u8], value_offset: u16, value_size: u32) -> Vec<u8> {
        let mut out = vec![name.len() as u8, index];
        out.extend(value_offset.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(value_size.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(name);
        out.resize(out.len().next_multiple_of(4), 0);
        out
    }

    #[test]
    fn parses_xattr_entries() {
        let mut region = xattr_entry(6, b"selinux", 64, 3);
        region.extend(xattr_entry(1, b"x", 72, 0));
        region.extend([0; 4]);
        region.resize(64, 0);
        region.extend(b"lbl\0\0\0\0\0");
        let mut xattrs = Xattrs::new();
        parse_xattrs(&region, 0, &region, &mut xattrs).unwrap();
        assert_eq!(xattrs[&b"security.selinux".to_vec()], b"lbl");
        assert_eq!(xattrs[&b"user.x".to_vec()], b"");

        // Values outside the region, missing terminators and duplicates are errors.
        let mut region = xattr_entry(6, b"selinux", 60000, 3);
        region.extend([0; 4]);
        assert!(parse_xattrs(&region, 0, &region, &mut Xattrs::new()).is_err());
        let region = xattr_entry(6, b"selinux", 0, 0);
        assert!(parse_xattrs(&region, 0, &region, &mut Xattrs::new()).is_err());
        let mut region = xattr_entry(1, b"a", 0, 0);
        region.extend(xattr_entry(1, b"a", 0, 0));
        region.extend([0; 4]);
        assert!(parse_xattrs(&region, 0, &region, &mut Xattrs::new()).is_err());
    }
}
