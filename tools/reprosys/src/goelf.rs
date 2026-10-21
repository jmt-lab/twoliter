//! Go build IDs in ELF binaries.
//!
//! Go stores a build ID of four parts in each binary's `.note.go.buildid`:
//! `actionID(binary)/actionID(main.a)/contentID(main.a)/contentID(binary)`. The linker derives the
//! GNU build ID (`.note.gnu.build-id`) from the output, which includes the Go build ID.
//!
//! Go 1.25 to 1.27 randomize the action IDs of binaries using cgo packages built with LTO
//! (golang/go#81040, fixed in Go 1.28), and with them the content IDs and the GNU build ID, so two
//! builds of such a binary differ only in their build IDs. Nothing reads the build IDs at run
//! time.

use crate::error::Result;
use snafu::{ensure_whatever, FromString, OptionExt, ResultExt, Whatever};
use std::ops::Range;

const GO_BUILD_ID_SECTION: &[u8] = b".note.go.buildid";
const GO_NOTE_NAME: &[u8] = b"Go\0\0";
const GO_NOTE_TYPE: u32 = 4;
const GNU_BUILD_ID_SECTION: &[u8] = b".note.gnu.build-id";
const GNU_NOTE_NAME: &[u8] = b"GNU\0";
const GNU_NOTE_TYPE: u32 = 3;
const SHT_NOTE: u32 = 7;

/// Whether `data` starts like an ELF file.
pub fn is_elf(data: &[u8]) -> bool {
    data.starts_with(b"\x7fELF")
}

/// A note section's descriptor: the bytes it holds and where.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Note {
    desc: Range<usize>,
}

/// A section header's name, type, file offset and size.
struct Section<'a> {
    name: &'a [u8],
    sh_type: u32,
    offset: u64,
    size: u64,
}

/// Reads the fields of an ELF file of either class and byte order.
struct Elf<'a> {
    data: &'a [u8],
    is_64: bool,
    big_endian: bool,
}

/// Add two offsets read from the file.
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).whatever_context("ELF offset overflows")
}

impl<'a> Elf<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        ensure_whatever!(is_elf(data) && data.len() >= 6, "not an ELF file");
        let is_64 = match data[4] {
            1 => false,
            2 => true,
            c => {
                snafu::whatever!("unknown ELF class {c}");
            }
        };
        let big_endian = match data[5] {
            1 => false,
            2 => true,
            d => {
                snafu::whatever!("unknown ELF byte order {d}");
            }
        };
        Ok(Self {
            data,
            is_64,
            big_endian,
        })
    }

    fn bytes(&self, offset: u64, len: usize) -> Result<&'a [u8]> {
        usize::try_from(offset)
            .ok()
            .and_then(|start| self.data.get(start..start.checked_add(len)?))
            .with_whatever_context(|| format!("ELF field at {offset:#x} is out of bounds"))
    }

    fn u16(&self, offset: u64) -> Result<u16> {
        let b: [u8; 2] = self.bytes(offset, 2)?.try_into().unwrap();
        Ok(if self.big_endian {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        })
    }

    fn u32(&self, offset: u64) -> Result<u32> {
        let b: [u8; 4] = self.bytes(offset, 4)?.try_into().unwrap();
        Ok(if self.big_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }

    /// A word: 8 bytes in ELF64, 4 in ELF32.
    fn word(&self, offset: u64) -> Result<u64> {
        if self.is_64 {
            let b: [u8; 8] = self.bytes(offset, 8)?.try_into().unwrap();
            Ok(if self.big_endian {
                u64::from_be_bytes(b)
            } else {
                u64::from_le_bytes(b)
            })
        } else {
            self.u32(offset).map(u64::from)
        }
    }

    /// Each section's name, type, file offset and size.
    fn sections(&self) -> Result<Vec<Section<'a>>> {
        let (shoff, shentsize, shnum, shstrndx) = if self.is_64 {
            (
                self.word(0x28)?,
                self.u16(0x3a)?,
                self.u16(0x3c)?,
                self.u16(0x3e)?,
            )
        } else {
            (
                self.word(0x20)?,
                self.u16(0x2e)?,
                self.u16(0x30)?,
                self.u16(0x32)?,
            )
        };
        let (offset_field, size_field) = if self.is_64 {
            (0x18, 0x20)
        } else {
            (0x10, 0x14)
        };
        let header = |i: u16| add(shoff, u64::from(i) * u64::from(shentsize));
        ensure_whatever!(shnum > 0 && shstrndx < shnum, "no section headers");
        let strtab_header = header(shstrndx)?;
        let strtab_offset = self.word(add(strtab_header, offset_field)?)?;
        let strtab_size = self.word(add(strtab_header, size_field)?)?;
        let strtab = self.bytes(
            strtab_offset,
            usize::try_from(strtab_size).whatever_context("section name table too large")?,
        )?;
        (0..shnum)
            .map(|i| {
                let h = header(i)?;
                let name_offset = self.u32(h)? as usize;
                let name = strtab
                    .get(name_offset..)
                    .and_then(|s| s.split(|&b| b == 0).next())
                    .with_whatever_context(|| format!("section {i} has an invalid name"))?;
                Ok(Section {
                    name,
                    sh_type: self.u32(add(h, 4)?)?,
                    offset: self.word(add(h, offset_field)?)?,
                    size: self.word(add(h, size_field)?)?,
                })
            })
            .collect()
    }

    /// The single note in the section named `section`, if there is one, checked to have the
    /// expected owner name and type.
    fn note(&self, section: &[u8], name: &[u8], note_type: u32) -> Result<Option<Note>> {
        let sections = self.sections()?;
        let mut matching = sections.iter().filter(|s| s.name == section);
        let Some(&Section {
            sh_type,
            offset,
            size,
            ..
        }) = matching.next()
        else {
            return Ok(None);
        };
        let section_name = String::from_utf8_lossy(section);
        ensure_whatever!(
            matching.next().is_none(),
            "more than one {section_name} section"
        );
        ensure_whatever!(sh_type == SHT_NOTE, "{section_name} is not a note section");
        let namesz = self.u32(offset)?;
        let descsz = self.u32(add(offset, 4)?)?;
        let found_type = self.u32(add(offset, 8)?)?;
        let name_start = add(offset, 12)?;
        let desc_start = add(name_start, u64::from(namesz.next_multiple_of(4)))?;
        let end = add(desc_start, u64::from(descsz.next_multiple_of(4)))?;
        ensure_whatever!(
            end <= add(offset, size)?
                && self.bytes(name_start, namesz as usize)? == name
                && found_type == note_type,
            "unexpected {section_name} note"
        );
        let desc = self.bytes(desc_start, descsz as usize)?;
        let desc_start = desc_start as usize;
        Ok(Some(Note {
            desc: desc_start..desc_start + desc.len(),
        }))
    }
}

/// A binary's Go build ID and the byte ranges of both build ID descriptors.
struct BuildIds<'a> {
    go: &'a str,
    masked: Vec<Range<usize>>,
}

fn build_ids(data: &[u8]) -> Result<Option<BuildIds<'_>>> {
    let elf = Elf::parse(data)?;
    let Some(go) = elf.note(GO_BUILD_ID_SECTION, GO_NOTE_NAME, GO_NOTE_TYPE)? else {
        return Ok(None);
    };
    let id =
        std::str::from_utf8(&data[go.desc.clone()]).whatever_context("Go build ID is not UTF-8")?;
    let mut masked = vec![go.desc];
    if let Some(gnu) = elf.note(GNU_BUILD_ID_SECTION, GNU_NOTE_NAME, GNU_NOTE_TYPE)? {
        masked.push(gnu.desc);
    }
    masked.sort_by_key(|r| r.start);
    ensure_whatever!(
        masked.windows(2).all(|w| w[0].end <= w[1].start),
        "build ID notes overlap"
    );
    Ok(Some(BuildIds { go: id, masked }))
}

/// Compare two ELF files that differ, when at least one is a Go binary.
///
/// Returns `None` when neither file has a Go build ID, so other rules apply. Otherwise returns
/// `Ok` with a description when the files differ only as golang/go#81040 explains: their Go build
/// IDs differ, and every byte outside the Go and GNU build ID descriptors is identical. Returns
/// `Err` with the reason otherwise.
pub fn compare_go_binaries(expected: &[u8], actual: &[u8]) -> Option<Result<String>> {
    let fail = |reason: String| Some(Err(Whatever::without_source(reason)));
    let (e, a) = match (build_ids(expected), build_ids(actual)) {
        (Ok(Some(e)), Ok(Some(a))) => (e, a),
        (Err(err), Ok(Some(_))) => return fail(format!("rebuilt binary: {err}")),
        (Ok(Some(_)), Err(err)) => return fail(format!("published binary: {err}")),
        (Ok(None), Ok(Some(_))) => {
            return fail("only the published binary has a Go build ID".into())
        }
        (Ok(Some(_)), Ok(None)) => return fail("only the rebuilt binary has a Go build ID".into()),
        _ => return None,
    };
    Some(describe(expected, actual, &e, &a))
}

fn describe(expected: &[u8], actual: &[u8], e: &BuildIds, a: &BuildIds) -> Result<String> {
    let e_parts: Vec<&str> = e.go.split('/').collect();
    let a_parts: Vec<&str> = a.go.split('/').collect();
    ensure_whatever!(
        e_parts.len() == 4 && a_parts.len() == 4,
        "Go build IDs {} vs {} do not have four parts",
        e.go,
        a.go
    );
    ensure_whatever!(
        e_parts[..2] != a_parts[..2],
        "Go build IDs are identical ({}), so the build IDs do not explain the difference",
        e.go
    );
    ensure_whatever!(
        expected.len() == actual.len() && e.masked == a.masked,
        "build ID notes differ in layout ({} vs {} bytes)",
        expected.len(),
        actual.len()
    );
    let mut start = 0;
    for range in e
        .masked
        .iter()
        .chain(std::iter::once(&(expected.len()..expected.len())))
    {
        let (e_span, a_span) = (&expected[start..range.start], &actual[start..range.start]);
        if let Some(i) = e_span.iter().zip(a_span).position(|(x, y)| x != y) {
            snafu::whatever!(
                "differs outside the build IDs, first at offset {:#x}",
                start + i
            );
        }
        start = range.end;
    }
    let differing: Vec<&str> = [
        "binary action ID",
        "main package action ID",
        "main package content ID",
        "binary content ID",
    ]
    .into_iter()
    .zip(e_parts.iter().zip(&a_parts))
    .filter(|(_, (x, y))| x != y)
    .map(|(name, _)| name)
    .collect();
    Ok(format!(
        "differs only in the Go build ID ({} vs {}; {} differ) and the GNU build ID. Go 1.25 to \
         1.27 randomize the build IDs of binaries using cgo packages built with LTO \
         (golang/go#81040)",
        e.go,
        a.go,
        differing.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ELF class and byte order.
    #[derive(Clone, Copy)]
    struct Format {
        is_64: bool,
        big_endian: bool,
    }

    const ELF64_LE: Format = Format {
        is_64: true,
        big_endian: false,
    };

    const FORMATS: [Format; 4] = [
        ELF64_LE,
        Format {
            is_64: true,
            big_endian: true,
        },
        Format {
            is_64: false,
            big_endian: false,
        },
        Format {
            is_64: false,
            big_endian: true,
        },
    ];

    /// Write the low `width` bytes of `value` at `at`.
    fn put(data: &mut [u8], at: usize, width: usize, value: u64, big_endian: bool) {
        if big_endian {
            data[at..at + width].copy_from_slice(&value.to_be_bytes()[8 - width..]);
        } else {
            data[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
        }
    }

    /// Build a minimal ELF file with a Go build ID note, a GNU build ID note and a `.text`
    /// section holding `text`.
    fn go_elf(build_id: &str, gnu_id: &[u8; 20], text: &[u8], format: Format) -> Vec<u8> {
        let Format { is_64, big_endian } = format;
        let (header_size, shentsize, word) = if is_64 { (64, 64, 8) } else { (52, 40, 4) };
        let (shoff_field, shentsize_field) = if is_64 { (0x28, 0x3a) } else { (0x20, 0x2e) };
        let (offset_field, size_field) = if is_64 { (0x18, 0x20) } else { (0x10, 0x14) };
        let note = |name: &[u8], ty: u32, desc: &[u8]| {
            let mut n = vec![0u8; 12];
            put(&mut n, 0, 4, name.len() as u64, big_endian);
            put(&mut n, 4, 4, desc.len() as u64, big_endian);
            put(&mut n, 8, 4, ty.into(), big_endian);
            n.extend(name);
            n.resize(n.len().next_multiple_of(4), 0);
            n.extend(desc);
            n.resize(n.len().next_multiple_of(4), 0);
            n
        };
        let strtab = b"\0.note.gnu.build-id\0.note.go.buildid\0.text\0.shstrtab\0".to_vec();
        let name_of = |s: &[u8]| strtab.windows(s.len()).position(|w| w == s).unwrap() as u64;
        let contents: Vec<(u64, u32, Vec<u8>)> = vec![
            (
                name_of(b".note.gnu.build-id"),
                SHT_NOTE,
                note(GNU_NOTE_NAME, GNU_NOTE_TYPE, gnu_id),
            ),
            (
                name_of(b".note.go.buildid"),
                SHT_NOTE,
                note(GO_NOTE_NAME, GO_NOTE_TYPE, build_id.as_bytes()),
            ),
            (name_of(b".text"), 1, text.to_vec()),
            (name_of(b".shstrtab"), 3, strtab.clone()),
        ];
        let mut data = vec![0u8; header_size];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = if is_64 { 2 } else { 1 };
        data[5] = if big_endian { 2 } else { 1 };
        let mut headers = vec![vec![0u8; shentsize]];
        for (name, ty, body) in &contents {
            let offset = data.len() as u64;
            data.extend(body);
            let mut h = vec![0u8; shentsize];
            put(&mut h, 0, 4, *name, big_endian);
            put(&mut h, 4, 4, (*ty).into(), big_endian);
            put(&mut h, offset_field, word, offset, big_endian);
            put(&mut h, size_field, word, body.len() as u64, big_endian);
            headers.push(h);
        }
        data.resize(data.len().next_multiple_of(8), 0);
        let shoff = data.len() as u64;
        put(&mut data, shoff_field, word, shoff, big_endian);
        put(&mut data, shentsize_field, 2, shentsize as u64, big_endian);
        put(
            &mut data,
            shentsize_field + 2,
            2,
            headers.len() as u64,
            big_endian,
        );
        put(
            &mut data,
            shentsize_field + 4,
            2,
            headers.len() as u64 - 1,
            big_endian,
        );
        data.extend(headers.concat());
        data
    }

    const REBUILT: &str =
        "OekQOI0MOb1L1q0FhHFu/hNEH2tEo8qcxP8hA3l_K/Q_z97QRB_xGDtgJGHBTy/d-BksYDz9tl4qL7vlNeh";
    const PUBLISHED: &str =
        "xDItdwtzBGChhBqMlNpC/z0GQ1EV_YXxQ5RJ6sZEy/Q_z97QRB_xGDtgJGHBTy/d-BksYDz9tl4qL7vlNeh";

    #[test]
    fn accepts_differing_action_ids() {
        let e = go_elf(REBUILT, &[1; 20], b"code", ELF64_LE);
        let a = go_elf(PUBLISHED, &[2; 20], b"code", ELF64_LE);
        let detail = compare_go_binaries(&e, &a).unwrap().unwrap();
        assert!(detail.contains("golang/go#81040"), "{detail}");
        assert!(
            detail.contains("; binary action ID, main package action ID differ)"),
            "{detail}"
        );

        let other_content = PUBLISHED.replace("d-Bks", "d-Bkt");
        let detail = compare_go_binaries(&e, &go_elf(&other_content, &[2; 20], b"code", ELF64_LE))
            .unwrap()
            .unwrap();
        assert!(detail.contains("binary content ID differ"), "{detail}");
    }

    #[test]
    fn reads_every_class_and_byte_order() {
        for format in FORMATS {
            let e = go_elf(REBUILT, &[1; 20], b"code", format);
            let a = go_elf(PUBLISHED, &[2; 20], b"code", format);
            assert!(compare_go_binaries(&e, &a).unwrap().is_ok());
            let other_code = go_elf(PUBLISHED, &[2; 20], b"c0de", format);
            let err = compare_go_binaries(&e, &other_code).unwrap().unwrap_err();
            assert!(err.to_string().contains("outside the build IDs"), "{err}");
        }
    }

    #[test]
    fn rejects_other_differences() {
        let e = go_elf(REBUILT, &[1; 20], b"code", ELF64_LE);

        let other_code = go_elf(PUBLISHED, &[2; 20], b"c0de", ELF64_LE);
        let err = compare_go_binaries(&e, &other_code).unwrap().unwrap_err();
        assert!(err.to_string().contains("outside the build IDs"), "{err}");

        let err = compare_go_binaries(&e, &go_elf(REBUILT, &[2; 20], b"code", ELF64_LE))
            .unwrap()
            .unwrap_err();
        assert!(err.to_string().contains("identical"), "{err}");

        let err = compare_go_binaries(&e, &go_elf("a/b", &[2; 20], b"code", ELF64_LE))
            .unwrap()
            .unwrap_err();
        assert!(err.to_string().contains("four parts"), "{err}");
    }

    #[test]
    fn rejects_overlapping_build_ids() {
        let gnu_note = [
            &4u32.to_le_bytes()[..],
            &20u32.to_le_bytes(),
            &GNU_NOTE_TYPE.to_le_bytes(),
            GNU_NOTE_NAME,
            &[b'x'; 20],
        ]
        .concat();
        let prefix = "aaaa/bbbb/cccc/";
        let id = format!("{prefix}{}", std::str::from_utf8(&gnu_note).unwrap());
        let mut data = go_elf(&id, &[1; 20], b"code", ELF64_LE);
        let shoff = u64::from_le_bytes(data[0x28..0x30].try_into().unwrap()) as usize;
        let go_header = shoff + 2 * 64;
        let go_offset = u64::from_le_bytes(data[go_header + 0x18..][..8].try_into().unwrap());
        let embedded = go_offset + 12 + GO_NOTE_NAME.len() as u64 + prefix.len() as u64;
        let gnu_header = shoff + 64;
        data[gnu_header + 0x18..][..8].copy_from_slice(&embedded.to_le_bytes());
        data[gnu_header + 0x20..][..8].copy_from_slice(&(gnu_note.len() as u64).to_le_bytes());

        let valid = go_elf(REBUILT, &[1; 20], b"code", ELF64_LE);
        let err = compare_go_binaries(&valid, &data).unwrap().unwrap_err();
        assert!(err.to_string().contains("build ID notes overlap"), "{err}");
    }

    #[test]
    fn rejects_overflowing_offsets() {
        let mut data = go_elf(REBUILT, &[1; 20], b"code", ELF64_LE);
        data[0x28..0x30].copy_from_slice(&(u64::MAX - 8).to_le_bytes());
        assert!(build_ids(&data).is_err());
    }

    #[test]
    fn ignores_files_without_go_build_ids() {
        assert!(compare_go_binaries(b"\x7fELFjunk", b"\x7fELFjunk2").is_none());
        let e = go_elf(REBUILT, &[1; 20], b"code", ELF64_LE);
        let err = compare_go_binaries(&e, b"\x7fELFjunk")
            .unwrap()
            .unwrap_err();
        assert!(err.to_string().contains("published binary"), "{err}");
    }
}
