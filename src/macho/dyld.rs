//! Dyld bind/export/chained-fixup blob decoding (`LC_DYLD_INFO`, `LC_DYLD_EXPORTS_TRIE`,
//! `LC_DYLD_CHAINED_FIXUPS`).
//!
//! These routines walk the compressed opcode streams described in Apple's dyld sources. They expose
//! decoded records for inspection; they do not apply relocations or resolve symbols at runtime.

use alloc::string::String;
use alloc::vec::Vec;

use crate::errors::FileParseError;

/// `BIND_OPCODE_*` immediate values for [`BindOpcode::SetDylibOrdinalImm`].
pub mod bind_imm {
    /// Self (main executable).
    pub const SELF: i8 = -1;
    /// Flat lookup (all symbols).
    pub const FLAT_LOOKUP: i8 = -2;
    /// Weak lookup.
    pub const WEAK_LOOKUP: i8 = -3;
}

/// One decoded bind opcode from a bind / lazy-bind / weak-bind stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindOpcode {
    /// `BIND_OPCODE_DONE` (0x00).
    Done,
    /// `BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB` (0x10).
    SetDylibOrdinalUleb(u64),
    /// `BIND_OPCODE_SET_DYLIB_ORDINAL_IMM` (0x40 | imm).
    SetDylibOrdinalImm(i8),
    /// `BIND_OPCODE_SET_DYLIB_SPECIAL_IMM` (0x30 | imm).
    SetDylibSpecialImm(i8),
    /// `BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM` (0x50 | flags).
    SetSymbolTrailingFlagsImm(u8),
    /// `BIND_OPCODE_SET_TYPE_IMM` (0x70 | type).
    SetTypeImm(u8),
    /// `BIND_OPCODE_SET_ADDEND_SLEB` (0x80).
    SetAddendSleb(i64),
    /// `BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB` (0x90).
    SetSegmentAndOffsetUleb {
        /// Segment index (0-based).
        segment: u64,
        /// Offset within the segment.
        offset: u64,
    },
    /// `BIND_OPCODE_ADD_ADDR_ULEB` (0xA0).
    AddAddrUleb(u64),
    /// `BIND_OPCODE_DO_BIND` (0xB0).
    DoBind,
    /// `BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB` (0xC0).
    DoBindAddAddrUleb(u64),
    /// `BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED` (0xD0 | scale).
    DoBindAddAddrImmScaled(u8),
    /// `BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB` (0xE0).
    DoBindUlebTimesSkippingUleb {
        /// Number of bind operations.
        count: u64,
        /// Bytes to skip after each bind.
        skip: u64,
    },
    /// Unrecognized opcode byte.
    Unknown(u8),
}

/// One exported symbol decoded from an export trie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportTrieEntry {
    /// Full exported name (path through the trie).
    pub name: String,
    /// Export flags (`EXPORT_SYMBOL_FLAGS_*`).
    pub flags: u64,
    /// In-image address (when not a re-export).
    pub address: Option<u64>,
    /// Re-export dylib ordinal (when `flags` indicates re-export).
    pub reexport_dylib: Option<u64>,
    /// Re-exported symbol name (when `flags` indicates re-export).
    pub reexport_name: Option<String>,
    /// Stub resolver offset (when `EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER` is set).
    pub resolver: Option<u64>,
}

const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

/// Decodes a bind / lazy-bind / weak-bind opcode stream.
pub fn decode_bind_opcodes(data: &[u8]) -> Result<Vec<BindOpcode>, FileParseError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let byte = data[pos];
        pos += 1;
        let op = match byte {
            0x00 => BindOpcode::Done,
            0x10 => {
                let (v, n) = read_uleb128(data, pos)?;
                pos += n;
                BindOpcode::SetDylibOrdinalUleb(v)
            }
            b if (b & 0xF0) == 0x40 => BindOpcode::SetDylibOrdinalImm((b & 0x0F) as i8),
            b if (b & 0xF0) == 0x30 => BindOpcode::SetDylibSpecialImm(-((b & 0x0F) as i8)),
            b if (b & 0xF0) == 0x50 => BindOpcode::SetSymbolTrailingFlagsImm(b & 0x0F),
            b if (b & 0xF0) == 0x70 => BindOpcode::SetTypeImm(b & 0x0F),
            0x80 => {
                let (v, n) = read_sleb128(data, pos)?;
                pos += n;
                BindOpcode::SetAddendSleb(v)
            }
            0x90 => {
                let (seg, n1) = read_uleb128(data, pos)?;
                pos += n1;
                let (off, n2) = read_uleb128(data, pos)?;
                pos += n2;
                BindOpcode::SetSegmentAndOffsetUleb {
                    segment: seg,
                    offset: off,
                }
            }
            0xA0 => {
                let (v, n) = read_uleb128(data, pos)?;
                pos += n;
                BindOpcode::AddAddrUleb(v)
            }
            0xB0 => BindOpcode::DoBind,
            0xC0 => {
                let (v, n) = read_uleb128(data, pos)?;
                pos += n;
                BindOpcode::DoBindAddAddrUleb(v)
            }
            b if (b & 0xF0) == 0xD0 => BindOpcode::DoBindAddAddrImmScaled(b & 0x0F),
            0xE0 => {
                let (count, n1) = read_uleb128(data, pos)?;
                pos += n1;
                let (skip, n2) = read_uleb128(data, pos)?;
                pos += n2;
                BindOpcode::DoBindUlebTimesSkippingUleb { count, skip }
            }
            other => BindOpcode::Unknown(other),
        };
        out.push(op);
        if matches!(out.last(), Some(BindOpcode::Done)) {
            break;
        }
    }
    Ok(out)
}

/// Decodes every exported symbol from an export trie blob.
pub fn decode_export_trie(data: &[u8]) -> Result<Vec<ExportTrieEntry>, FileParseError> {
    let mut out = Vec::new();
    let mut pending = alloc::vec![(0usize, String::new())];
    let mut visited = alloc::vec![false; data.len()];
    while let Some((node_offset, prefix)) = pending.pop() {
        if node_offset >= data.len() {
            return Err(FileParseError::BufferOverflow);
        }
        if visited[node_offset] {
            return Err(FileParseError::InvalidFileFormat);
        }
        visited[node_offset] = true;

        let mut pos = node_offset;
        let terminal_size = if data[pos] & 0x80 != 0 {
            let (value, width) = read_uleb128(data, pos)?;
            pos += width;
            usize::try_from(value).map_err(|_| FileParseError::BufferOverflow)?
        } else {
            let value = data[pos] as usize;
            pos += 1;
            value
        };

        if terminal_size > 0 {
            let term_end = pos
                .checked_add(terminal_size)
                .ok_or(FileParseError::BufferOverflow)?;
            let term = data
                .get(pos..term_end)
                .ok_or(FileParseError::BufferOverflow)?;
            pos = term_end;
            if let Some(entry) = parse_terminal_export(prefix.clone(), term)? {
                out.push(entry);
            }
        }

        let Some(&child_count) = data.get(pos) else {
            continue;
        };
        pos += 1;
        let mut children = Vec::with_capacity(child_count as usize);
        for _ in 0..child_count {
            let tail = data.get(pos..).ok_or(FileParseError::BufferOverflow)?;
            let end = tail
                .iter()
                .position(|b| *b == 0)
                .ok_or(FileParseError::BufferOverflow)?;
            let edge = core::str::from_utf8(&tail[..end])
                .map_err(|_| FileParseError::InvalidFileFormat)?;
            pos += end + 1;
            let (child_offset, width) = read_uleb128(data, pos)?;
            pos += width;
            let child_offset =
                usize::try_from(child_offset).map_err(|_| FileParseError::BufferOverflow)?;
            let mut child_prefix = prefix.clone();
            child_prefix.push_str(edge);
            children.push((child_offset, child_prefix));
        }
        pending.extend(children.into_iter().rev());
    }
    Ok(out)
}

fn parse_terminal_export(
    name: String,
    term: &[u8],
) -> Result<Option<ExportTrieEntry>, FileParseError> {
    if term.is_empty() {
        return Ok(None);
    }
    let (flags, n1) = read_uleb128(term, 0)?;
    let mut pos = n1;

    if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
        let (dylib, n2) = read_uleb128(term, pos)?;
        pos += n2;
        let reexport_name = read_cstring(term, pos)?;
        return Ok(Some(ExportTrieEntry {
            name,
            flags,
            address: None,
            reexport_dylib: Some(dylib),
            reexport_name: Some(reexport_name),
            resolver: None,
        }));
    }

    let (address, n3) = read_uleb128(term, pos)?;
    pos += n3;
    let resolver = if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
        let (r, n4) = read_uleb128(term, pos)?;
        pos += n4;
        Some(r)
    } else {
        None
    };
    let _ = pos;

    Ok(Some(ExportTrieEntry {
        name,
        flags,
        address: Some(address),
        reexport_dylib: None,
        reexport_name: None,
        resolver,
    }))
}

fn read_cstring(data: &[u8], offset: usize) -> Result<String, FileParseError> {
    let slice = data.get(offset..).ok_or(FileParseError::BufferOverflow)?;
    let stop = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Ok(String::from_utf8_lossy(&slice[..stop]).into_owned())
}

fn read_uleb128(data: &[u8], mut offset: usize) -> Result<(u64, usize), FileParseError> {
    let start = offset;
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(offset).ok_or(FileParseError::BufferOverflow)?;
        offset += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(FileParseError::InvalidFileFormat);
        }
    }
    Ok((result, offset - start))
}

fn read_sleb128(data: &[u8], mut offset: usize) -> Result<(i64, usize), FileParseError> {
    let start = offset;
    let mut result = 0i64;
    let mut shift = 0u32;
    let mut byte;
    loop {
        byte = *data.get(offset).ok_or(FileParseError::BufferOverflow)?;
        offset += 1;
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err(FileParseError::InvalidFileFormat);
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok((result, offset - start))
}

/// `dyld_chained_fixups_header.imports_format`: 32-bit `dyld_chained_import` records.
pub const DYLD_CHAINED_IMPORT: u32 = 1;
/// `dyld_chained_fixups_header.imports_format`: `dyld_chained_import_addend` records.
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
/// `dyld_chained_fixups_header.imports_format`: `dyld_chained_import_addend64` records.
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

/// Stride 8; unauthenticated rebase targets are vmaddrs.
pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
/// Stride 4; rebase targets are vmaddrs.
pub const DYLD_CHAINED_PTR_64: u16 = 2;
/// Stride 4, 32-bit words; rebase targets are vmaddrs.
pub const DYLD_CHAINED_PTR_32: u16 = 3;
/// Stride 4, 32-bit dyld shared cache words.
pub const DYLD_CHAINED_PTR_32_CACHE: u16 = 4;
/// Stride 4, 32-bit firmware words.
pub const DYLD_CHAINED_PTR_32_FIRMWARE: u16 = 5;
/// Stride 4; rebase targets are image offsets.
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
/// Stride 4; unauthenticated rebase targets are image offsets.
pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
/// Stride 4; kernel collection rebases relative to a cache level.
pub const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u16 = 8;
/// Stride 8; unauthenticated rebase targets are image offsets.
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
/// Stride 4; unauthenticated rebase targets are vmaddrs.
pub const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u16 = 10;
/// Stride 1; x86-64 kernel collection rebases relative to a cache level.
pub const DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: u16 = 11;
/// Stride 8; image-offset rebase targets and 24-bit bind ordinals.
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;
/// Stride 8; dyld shared cache rebases (A keys only).
pub const DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE: u16 = 13;
/// Stride 4; rebase targets are segment index/offset pairs.
pub const DYLD_CHAINED_PTR_ARM64E_SEGMENTED: u16 = 14;

/// `page_start[]` value for a page without fixups.
pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xffff;
/// `page_start[]` flag: the low 15 bits index a multi-start list in the same table.
pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;
/// Multi-start list flag marking the final start for a page.
pub const DYLD_CHAINED_PTR_START_LAST: u16 = 0x8000;

/// Chain stride in bytes for a pointer format, or `None` when the format is unknown.
pub fn chained_pointer_stride(format: u16) -> Option<u16> {
    match format {
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24
        | DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE => Some(8),
        DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => Some(1),
        2..=8 | DYLD_CHAINED_PTR_ARM64E_FIRMWARE | DYLD_CHAINED_PTR_ARM64E_SEGMENTED => Some(4),
        _ => None,
    }
}

/// On-disk pointer slot width in bytes (4 for the 32-bit formats, otherwise 8).
pub fn chained_pointer_width(format: u16) -> usize {
    match format {
        DYLD_CHAINED_PTR_32 | DYLD_CHAINED_PTR_32_CACHE | DYLD_CHAINED_PTR_32_FIRMWARE => 4,
        _ => 8,
    }
}

/// One chained import record. All three import formats decode to this shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainedImport {
    /// Dependency ordinal: positive values are one-based, `0` is self and
    /// `-1..=-15` are the special `BIND_SPECIAL_DYLIB_*` values.
    pub library_ordinal: i32,
    /// Whether missing symbols are permitted.
    pub weak: bool,
    /// Import addend (zero for `DYLD_CHAINED_IMPORT`).
    pub addend: i64,
    /// Imported symbol name.
    pub name: String,
}
/// `dyld_chained_starts_in_segment` for one segment with pointer chains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainedSegment {
    /// Zero-based load-command segment index.
    pub segment_index: usize,
    /// Page size (normally 4096 or 16384).
    pub page_size: u16,
    /// `DYLD_CHAINED_PTR_*` format of every chain in this segment.
    pub pointer_format: u16,
    /// Preferred virtual offset from the Mach header mapping.
    pub segment_offset: u64,
    /// For 32-bit formats, rebase targets above this value are not pointers.
    pub max_valid_pointer: u32,
    /// Number of pages described by `page_starts`.
    pub page_count: u16,
    /// Raw `page_start[]` table as stored: `page_count` entries followed by any
    /// multi-start lists. Use [`ChainedSegment::chain_starts`] to resolve a page.
    pub page_starts: Vec<u16>,
}

impl ChainedSegment {
    /// Chain-start byte offsets within `page`. Empty for pages without fixups or
    /// out-of-range pages; multi-start lists were validated by the decoder.
    pub fn chain_starts(&self, page: usize) -> ChainStarts<'_> {
        let mut starts = ChainStarts {
            table: &self.page_starts,
            next: None,
            single: None,
        };
        if page >= usize::from(self.page_count) {
            return starts;
        }
        match self.page_starts.get(page).copied() {
            Some(DYLD_CHAINED_PTR_START_NONE) | None => {}
            Some(start) if start & DYLD_CHAINED_PTR_START_MULTI != 0 => {
                starts.next = Some(usize::from(start & !DYLD_CHAINED_PTR_START_MULTI));
            }
            Some(start) => starts.single = Some(start),
        }
        starts
    }

    /// Decodes one pointer word from this segment's chains.
    pub fn decode_pointer(&self, word: u64) -> Result<ChainedPointer, FileParseError> {
        decode_chained_pointer_as(self.pointer_format, self.max_valid_pointer, word)
    }
}

/// Iterator over chain-start offsets in one page; see [`ChainedSegment::chain_starts`].
#[derive(Clone, Debug)]
pub struct ChainStarts<'a> {
    table: &'a [u16],
    next: Option<usize>,
    single: Option<u16>,
}

impl Iterator for ChainStarts<'_> {
    type Item = u16;
    fn next(&mut self) -> Option<u16> {
        if let Some(start) = self.single.take() {
            return Some(start);
        }
        let index = self.next?;
        let entry = *self.table.get(index)?;
        self.next = (entry & DYLD_CHAINED_PTR_START_LAST == 0).then_some(index + 1);
        Some(entry & !DYLD_CHAINED_PTR_START_LAST)
    }
}

/// Parsed `LC_DYLD_CHAINED_FIXUPS` metadata. Pointer words remain in mapped segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainedFixups {
    /// `DYLD_CHAINED_IMPORT*` encoding of the import table.
    pub imports_format: u32,
    /// Imported symbol records in pointer ordinal order.
    pub imports: Vec<ChainedImport>,
    /// Segments containing runtime pointer chains.
    pub segments: Vec<ChainedSegment>,
}
/// Decodes version-zero chained-fixup metadata with uncompressed symbol names.
/// All `DYLD_CHAINED_IMPORT*` encodings, all `DYLD_CHAINED_PTR_*` formats in
/// Apple's `fixup-chains.h` (1 through 14) and multi-start pages are accepted;
/// zlib-compressed symbol pools are unsupported.
/// Copied names (including their terminators) and decoded page tables share an
/// eight-times-input-size budget. Excessive alias expansion returns `ValueTooLarge`.
pub fn decode_chained_fixups(data: &[u8]) -> Result<ChainedFixups, FileParseError> {
    fn bytes<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], FileParseError> {
        data.get(
            offset
                ..offset
                    .checked_add(N)
                    .ok_or(FileParseError::BufferOverflow)?,
        )
        .ok_or(FileParseError::BufferOverflow)?
        .try_into()
        .map_err(|_| FileParseError::BufferOverflow)
    }
    fn word(data: &[u8], offset: usize) -> Result<u32, FileParseError> {
        bytes(data, offset).map(u32::from_le_bytes)
    }
    fn half(data: &[u8], offset: usize) -> Result<u16, FileParseError> {
        bytes(data, offset).map(u16::from_le_bytes)
    }
    fn quad(data: &[u8], offset: usize) -> Result<u64, FileParseError> {
        bytes(data, offset).map(u64::from_le_bytes)
    }
    let imports_format = word(data, 20)?;
    let record_size = match imports_format {
        DYLD_CHAINED_IMPORT => 4,
        DYLD_CHAINED_IMPORT_ADDEND => 8,
        DYLD_CHAINED_IMPORT_ADDEND64 => 16,
        _ => 0,
    };
    if word(data, 0)? != 0 || record_size == 0 {
        return Err(FileParseError::UnsupportedFeature(String::from(
            "chained fixup encoding",
        )));
    }
    if word(data, 24)? != 0 {
        return Err(FileParseError::UnsupportedFeature(String::from(
            "compressed chained fixup symbols",
        )));
    }
    // Count bounds alone do not bound allocation: imports can share a long name,
    // and many segment records can alias the same page-start array.
    let mut remaining = data.len().saturating_mul(8);
    let imports_offset = word(data, 8)? as usize;
    let symbols_offset = word(data, 12)? as usize;
    let count = word(data, 16)? as usize;
    if count > data.len() / record_size {
        return Err(FileParseError::BufferOverflow);
    }
    let imports_end = count
        .checked_mul(record_size)
        .and_then(|size| imports_offset.checked_add(size))
        .ok_or(FileParseError::BufferOverflow)?;
    data.get(imports_offset..imports_end)
        .ok_or(FileParseError::BufferOverflow)?;
    let mut imports = Vec::new();
    for i in 0..count {
        let at = imports_offset + i * record_size;
        // Ordinals above the special range are unsigned (-15..=240, -15..=65520).
        let (ordinal, weak, name_offset, addend) = if imports_format == DYLD_CHAINED_IMPORT_ADDEND64
        {
            let raw = quad(data, at)?;
            let ordinal = raw as u16;
            let ordinal = if ordinal > 0xfff0 {
                i32::from(ordinal as i16)
            } else {
                i32::from(ordinal)
            };
            (
                ordinal,
                raw & 0x10000 != 0,
                (raw >> 32) as usize,
                quad(data, at + 8)? as i64,
            )
        } else {
            let raw = word(data, at)?;
            let ordinal = raw as u8;
            let ordinal = if ordinal > 0xf0 {
                i32::from(ordinal as i8)
            } else {
                i32::from(ordinal)
            };
            let addend = if imports_format == DYLD_CHAINED_IMPORT_ADDEND {
                i64::from(word(data, at + 4)? as i32)
            } else {
                0
            };
            (ordinal, raw & 256 != 0, (raw >> 9) as usize, addend)
        };
        let offset = symbols_offset
            .checked_add(name_offset)
            .ok_or(FileParseError::BufferOverflow)?;
        let tail = data.get(offset..).ok_or(FileParseError::BufferOverflow)?;
        let end = tail
            .iter()
            .take(remaining.saturating_add(1))
            .position(|b| *b == 0)
            .ok_or(if tail.len() <= remaining {
                FileParseError::BufferOverflow
            } else {
                FileParseError::ValueTooLarge
            })?;
        remaining = remaining
            .checked_sub(end + 1)
            .ok_or(FileParseError::ValueTooLarge)?;
        imports.push(ChainedImport {
            library_ordinal: ordinal,
            weak,
            addend,
            name: core::str::from_utf8(&tail[..end])
                .map_err(|_| FileParseError::InvalidFileFormat)?
                .into(),
        });
    }
    let starts = word(data, 4)? as usize;
    let count = word(data, starts)? as usize;
    if count > data.len() / 4 {
        return Err(FileParseError::BufferOverflow);
    }
    let starts_end = count
        .checked_mul(4)
        .and_then(|size| size.checked_add(4))
        .and_then(|size| starts.checked_add(size))
        .ok_or(FileParseError::BufferOverflow)?;
    data.get(starts..starts_end)
        .ok_or(FileParseError::BufferOverflow)?;
    let mut segments = Vec::new();
    for i in 0..count {
        let offset = word(
            data,
            starts
                .checked_add(4 + i * 4)
                .ok_or(FileParseError::BufferOverflow)?,
        )? as usize;
        if offset == 0 {
            continue;
        }
        let offset = starts
            .checked_add(offset)
            .ok_or(FileParseError::BufferOverflow)?;
        let size = word(data, offset)? as usize;
        let segment_data = data
            .get(
                offset
                    ..offset
                        .checked_add(size)
                        .ok_or(FileParseError::BufferOverflow)?,
            )
            .ok_or(FileParseError::BufferOverflow)?;
        let page_size = half(segment_data, 4)?;
        let pointer_format = half(segment_data, 6)?;
        if chained_pointer_stride(pointer_format).is_none() {
            return Err(FileParseError::UnsupportedFeature(String::from(
                "chained pointer format",
            )));
        }
        if page_size == 0 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let segment_offset = quad(segment_data, 8)?;
        let max_valid_pointer = word(segment_data, 16)?;
        let page_count = half(segment_data, 20)?;
        // The table runs to the end of the record so multi-start lists are kept.
        let entries = segment_data.len().saturating_sub(22) / 2;
        if entries < usize::from(page_count) {
            return Err(FileParseError::BufferOverflow);
        }
        remaining = remaining
            .checked_sub(entries * core::mem::size_of::<u16>())
            .ok_or(FileParseError::ValueTooLarge)?;
        let page_starts = (0..entries)
            .map(|p| half(segment_data, 22 + p * 2))
            .collect::<Result<Vec<_>, _>>()?;
        // The x86-64 kernel cache stride is one byte; other chains are word aligned.
        let align = if pointer_format == DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE {
            1
        } else {
            4
        };
        let valid = |start: u16| start < page_size && start.is_multiple_of(align);
        for &start in &page_starts[..usize::from(page_count)] {
            if start == DYLD_CHAINED_PTR_START_NONE {
                continue;
            }
            if start & DYLD_CHAINED_PTR_START_MULTI == 0 {
                if !valid(start) {
                    return Err(FileParseError::InvalidFileFormat);
                }
                continue;
            }
            // Multi-start lists live after the per-page entries and end with START_LAST.
            let mut index = usize::from(start & !DYLD_CHAINED_PTR_START_MULTI);
            if index < usize::from(page_count) {
                return Err(FileParseError::InvalidFileFormat);
            }
            loop {
                let entry = *page_starts
                    .get(index)
                    .ok_or(FileParseError::InvalidFileFormat)?;
                if !valid(entry & !DYLD_CHAINED_PTR_START_LAST) {
                    return Err(FileParseError::InvalidFileFormat);
                }
                if entry & DYLD_CHAINED_PTR_START_LAST != 0 {
                    break;
                }
                index += 1;
            }
        }
        segments.push(ChainedSegment {
            segment_index: i,
            page_size,
            pointer_format,
            segment_offset,
            max_valid_pointer,
            page_count,
            page_starts,
        });
    }
    Ok(ChainedFixups {
        imports_format,
        imports,
        segments,
    })
}

/// One pointer slot reached by walking a segment's chains.
#[derive(Clone, Debug)]
pub struct ChainedFixupSlot {
    /// Zero-based load-command segment index.
    pub segment_index: usize,
    /// `DYLD_CHAINED_PTR_*` format of the containing chain.
    pub pointer_format: u16,
    /// Slot offset from the preferred Mach header mapping.
    pub vm_offset: u64,
    /// On-disk pointer word; `size` is 4 for 32-bit formats and 8 otherwise.
    pub raw: crate::field::Field<u64>,
    /// Decoded word.
    pub pointer: ChainedPointer,
}

impl ChainedFixupSlot {
    /// Unslid rebase target address for an image loaded at its preferred
    /// `image_base`, including `high8`. `None` for binds, non-pointers and
    /// rebases relative to other images (kernel cache levels, segment tables).
    pub fn rebase_vmaddr(&self, image_base: u64) -> Option<u64> {
        match self.pointer {
            ChainedPointer::Rebase { target, high8, .. } => {
                let vmaddr = matches!(
                    self.pointer_format,
                    DYLD_CHAINED_PTR_ARM64E
                        | DYLD_CHAINED_PTR_64
                        | DYLD_CHAINED_PTR_32
                        | DYLD_CHAINED_PTR_32_FIRMWARE
                        | DYLD_CHAINED_PTR_ARM64E_FIRMWARE
                );
                let address = if vmaddr {
                    target
                } else {
                    image_base.checked_add(target)?
                };
                Some(address | u64::from(high8) << 56)
            }
            ChainedPointer::AuthRebase { target, .. } => image_base.checked_add(target),
            _ => None,
        }
    }
}

impl<B: core::ops::Deref<Target = [u8]>> super::MachO<B> {
    /// Lazily decodes `LC_DYLD_CHAINED_FIXUPS` metadata.
    pub fn chained_fixups(&self) -> Result<Option<ChainedFixups>, FileParseError> {
        for cmd in &self.load_commands {
            if cmd.cmd.value != 0x80000034 {
                continue;
            }
            let offset = cmd.offset();
            if cmd.cmdsize.value < 16 {
                return Err(FileParseError::InvalidFileFormat);
            }
            let order = self.byte_order();
            let start = order.read_u32(&self.buffer, offset + 8)? as usize;
            let size = order.read_u32(&self.buffer, offset + 12)? as usize;
            let end = start
                .checked_add(size)
                .ok_or(FileParseError::BufferOverflow)?;
            return decode_chained_fixups(
                self.buffer
                    .get(start..end)
                    .ok_or(FileParseError::BufferOverflow)?,
            )
            .map(Some);
        }
        Ok(None)
    }

    /// Walks every chain described by [`MachO::chained_fixups`](super::MachO::chained_fixups)
    /// and decodes each slot in the file buffer. Slots must be file-backed and
    /// stay within their page; bind ordinals must index the import table.
    /// Returns `Ok(None)` when the image has no `LC_DYLD_CHAINED_FIXUPS`.
    pub fn chained_fixup_slots(&self) -> Result<Option<Vec<ChainedFixupSlot>>, FileParseError> {
        let Some(fixups) = self.chained_fixups()? else {
            return Ok(None);
        };
        let order = self.byte_order();
        // Chains are monotone within a page, but aliased segment records or
        // repeated multi-starts may revisit bytes; bound total work by file size.
        let mut remaining = self.buffer.len();
        let mut slots = Vec::new();
        for starts in &fixups.segments {
            let segment = self
                .segments
                .get(starts.segment_index)
                .ok_or(FileParseError::InvalidFileFormat)?;
            let width = chained_pointer_width(starts.pointer_format) as u64;
            let page_size = u64::from(starts.page_size);
            for page in 0..usize::from(starts.page_count) {
                let page_start = (page as u64) * page_size;
                let page_end = page_start + page_size;
                for start in starts.chain_starts(page) {
                    let mut offset = page_start + u64::from(start);
                    loop {
                        remaining = remaining
                            .checked_sub(1)
                            .ok_or(FileParseError::ValueTooLarge)?;
                        let end = offset + width;
                        if end > page_end || end > segment.filesize() || end > segment.vmsize() {
                            return Err(FileParseError::InvalidFileFormat);
                        }
                        let file_offset = segment
                            .fileoff()
                            .checked_add(offset)
                            .and_then(|o| usize::try_from(o).ok())
                            .ok_or(FileParseError::BufferOverflow)?;
                        let word = if width == 4 {
                            u64::from(order.read_u32(&self.buffer, file_offset)?)
                        } else {
                            order.read_u64(&self.buffer, file_offset)?
                        };
                        let pointer = starts.decode_pointer(word)?;
                        let (ordinal, next) = match pointer {
                            ChainedPointer::Bind { ordinal, next, .. }
                            | ChainedPointer::AuthBind { ordinal, next, .. } => {
                                (Some(ordinal), next)
                            }
                            ChainedPointer::Rebase { next, .. }
                            | ChainedPointer::AuthRebase { next, .. }
                            | ChainedPointer::CacheRebase { next, .. }
                            | ChainedPointer::SegmentedRebase { next, .. }
                            | ChainedPointer::NonPointer { next, .. } => (None, next),
                        };
                        if ordinal.is_some_and(|o| o as usize >= fixups.imports.len()) {
                            return Err(FileParseError::InvalidFileFormat);
                        }
                        slots.push(ChainedFixupSlot {
                            segment_index: starts.segment_index,
                            pointer_format: starts.pointer_format,
                            vm_offset: starts
                                .segment_offset
                                .checked_add(offset)
                                .ok_or(FileParseError::BufferOverflow)?,
                            raw: crate::field::Field::new(word, file_offset, width as usize),
                            pointer,
                        });
                        if next == 0 {
                            break;
                        }
                        offset += u64::from(next);
                    }
                }
            }
        }
        Ok(Some(slots))
    }
}

/// Pointer-authentication key encoded in an authenticated chained pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerAuthKey {
    /// Instruction key A (`IA`).
    IA,
    /// Instruction key B (`IB`).
    IB,
    /// Data key A (`DA`).
    DA,
    /// Data key B (`DB`).
    DB,
}

impl PointerAuthKey {
    fn from_bits(bits: u64) -> Self {
        match bits & 3 {
            0 => Self::IA,
            1 => Self::IB,
            2 => Self::DA,
            _ => Self::DB,
        }
    }
}

/// Signing schema of an authenticated chained pointer. The PAC itself is
/// computed by dyld at load time and is not stored in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PointerAuth {
    /// Signing key.
    pub key: PointerAuthKey,
    /// Constant 16-bit discriminator.
    pub diversity: u16,
    /// Whether the slot address is blended into the discriminator.
    pub address_diversity: bool,
}

impl PointerAuth {
    /// Discriminator dyld passes to the `PAC*` instruction for a slot at the
    /// runtime address `slot_address` (`ptrauth_blend_discriminator` when
    /// address-diversified).
    pub fn discriminator(&self, slot_address: u64) -> u64 {
        if self.address_diversity {
            (slot_address & 0x0000_ffff_ffff_ffff) | u64::from(self.diversity) << 48
        } else {
            u64::from(self.diversity)
        }
    }

    fn from_word(word: u64, diversity_shift: u32) -> Self {
        PointerAuth {
            key: PointerAuthKey::from_bits(word >> (diversity_shift + 17)),
            diversity: (word >> diversity_shift) as u16,
            address_diversity: (word >> (diversity_shift + 16)) & 1 != 0,
        }
    }
}

/// One decoded chained pointer word. `next` is the byte distance to the next
/// slot in the same page (already multiplied by the format stride), or zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainedPointer {
    /// Bind to an import-table ordinal with an embedded addend.
    Bind {
        /// Zero-based chained import index.
        ordinal: u32,
        /// Embedded addend (unsigned 8/6-bit or signed 19-bit, per format).
        addend: i64,
        /// Distance to next pointer, or zero to end the chain.
        next: u16,
    },
    /// Rebase; see [`ChainedFixupSlot::rebase_vmaddr`] for target semantics.
    Rebase {
        /// Vmaddr or image-relative offset, depending on the pointer format.
        target: u64,
        /// Top eight bits of the unslid pointer.
        high8: u8,
        /// Distance to next pointer, or zero to end the chain.
        next: u16,
    },
    /// Authenticated bind (arm64e).
    AuthBind {
        /// Zero-based chained import index.
        ordinal: u32,
        /// Signing schema.
        auth: PointerAuth,
        /// Distance to next pointer, or zero to end the chain.
        next: u16,
    },
    /// Authenticated rebase (arm64e); the target is always an image offset.
    AuthRebase {
        /// Image-relative (or shared-cache-relative) target offset.
        target: u64,
        /// Signing schema.
        auth: PointerAuth,
        /// Distance to next pointer, or zero to end the chain.
        next: u16,
    },
    /// Kernel collection rebase relative to `basePointers[cache_level]`.
    CacheRebase {
        /// Offset from the selected cache level's Mach header.
        target: u64,
        /// Index of the kernel collection level.
        cache_level: u8,
        /// Signing schema when authenticated.
        auth: Option<PointerAuth>,
        /// Distance to next pointer, or zero to end the chain.
        next: u16,
    },
    /// `DYLD_CHAINED_PTR_ARM64E_SEGMENTED` rebase into a segment address table.
    SegmentedRebase {
        /// Index into the segment address table.
        target_segment: u8,
        /// Offset within that segment.
        target_offset: u32,
        /// Signing schema when authenticated.
        auth: Option<PointerAuth>,
        /// Distance to next pointer, or zero to end the chain.
        next: u16,
    },
    /// `DYLD_CHAINED_PTR_32` out-of-range rebase that encodes a plain value.
    NonPointer {
        /// Restored value (target minus `(64MB + max_valid_pointer) / 2`).
        value: u32,
        /// Distance to next pointer, or zero to end the chain.
        next: u16,
    },
}

/// Decodes one `DYLD_CHAINED_PTR_64_OFFSET` word; see [`decode_chained_pointer_as`].
pub fn decode_chained_pointer(word: u64) -> Result<ChainedPointer, FileParseError> {
    decode_chained_pointer_as(DYLD_CHAINED_PTR_64_OFFSET, 0, word)
}

/// Decodes one chain word in `format`, rejecting nonzero reserved bits.
/// 32-bit formats use the low 32 bits of `word`; `max_valid_pointer` only
/// affects `DYLD_CHAINED_PTR_32` (zero disables non-pointer detection).
pub fn decode_chained_pointer_as(
    format: u16,
    max_valid_pointer: u32,
    word: u64,
) -> Result<ChainedPointer, FileParseError> {
    let bits = |shift: u32, width: u32| (word >> shift) & ((1u64 << width) - 1);
    let stride = u64::from(chained_pointer_stride(format).ok_or_else(|| {
        FileParseError::UnsupportedFeature(String::from("chained pointer format"))
    })?);
    let scaled = |next: u64| (next * stride) as u16;
    match format {
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => {
            let next = scaled(bits(51, 12));
            if word >> 63 != 0 {
                if bits(32, 19) != 0 {
                    return Err(FileParseError::InvalidFileFormat);
                }
                Ok(ChainedPointer::Bind {
                    ordinal: bits(0, 24) as u32,
                    addend: bits(24, 8) as i64,
                    next,
                })
            } else {
                if bits(44, 7) != 0 {
                    return Err(FileParseError::InvalidFileFormat);
                }
                Ok(ChainedPointer::Rebase {
                    target: bits(0, 36),
                    high8: bits(36, 8) as u8,
                    next,
                })
            }
        }
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_KERNEL
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_FIRMWARE
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => {
            let next = scaled(bits(51, 11));
            let ordinal_bits = if format == DYLD_CHAINED_PTR_ARM64E_USERLAND24 {
                24
            } else {
                16
            };
            let (auth, bind) = (word >> 63 != 0, (word >> 62) & 1 != 0);
            if bind && bits(ordinal_bits, 32 - ordinal_bits) != 0 {
                return Err(FileParseError::InvalidFileFormat);
            }
            let ordinal = bits(0, ordinal_bits) as u32;
            Ok(match (auth, bind) {
                (true, true) => ChainedPointer::AuthBind {
                    ordinal,
                    auth: PointerAuth::from_word(word, 32),
                    next,
                },
                (true, false) => ChainedPointer::AuthRebase {
                    target: bits(0, 32),
                    auth: PointerAuth::from_word(word, 32),
                    next,
                },
                (false, true) => ChainedPointer::Bind {
                    ordinal,
                    // Sign-extend the 19-bit addend.
                    addend: ((bits(32, 19) << 45) as i64) >> 45,
                    next,
                },
                (false, false) => ChainedPointer::Rebase {
                    target: bits(0, 43),
                    high8: bits(43, 8) as u8,
                    next,
                },
            })
        }
        DYLD_CHAINED_PTR_64_KERNEL_CACHE | DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => {
            Ok(ChainedPointer::CacheRebase {
                target: bits(0, 30),
                cache_level: bits(30, 2) as u8,
                auth: (word >> 63 != 0).then(|| PointerAuth::from_word(word, 32)),
                next: scaled(bits(51, 12)),
            })
        }
        DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE => {
            let next = scaled(bits(52, 11));
            if word >> 63 != 0 {
                Ok(ChainedPointer::AuthRebase {
                    target: bits(0, 34),
                    auth: PointerAuth {
                        key: if bits(51, 1) != 0 {
                            PointerAuthKey::DA
                        } else {
                            PointerAuthKey::IA
                        },
                        diversity: bits(34, 16) as u16,
                        address_diversity: bits(50, 1) != 0,
                    },
                    next,
                })
            } else {
                if bits(42, 10) != 0 {
                    return Err(FileParseError::InvalidFileFormat);
                }
                Ok(ChainedPointer::Rebase {
                    target: bits(0, 34),
                    high8: bits(34, 8) as u8,
                    next,
                })
            }
        }
        DYLD_CHAINED_PTR_ARM64E_SEGMENTED => {
            let auth = word >> 63 != 0;
            if !auth && bits(32, 19) != 0 {
                return Err(FileParseError::InvalidFileFormat);
            }
            Ok(ChainedPointer::SegmentedRebase {
                target_segment: bits(28, 4) as u8,
                target_offset: bits(0, 28) as u32,
                auth: auth.then(|| PointerAuth::from_word(word, 32)),
                next: scaled(bits(51, 12)),
            })
        }
        DYLD_CHAINED_PTR_32 => {
            let next = scaled(bits(26, 5));
            if bits(31, 1) != 0 {
                return Ok(ChainedPointer::Bind {
                    ordinal: bits(0, 20) as u32,
                    addend: bits(20, 6) as i64,
                    next,
                });
            }
            let target = bits(0, 26) as u32;
            if max_valid_pointer != 0 && target > max_valid_pointer {
                let bias = (0x0400_0000 + max_valid_pointer) / 2;
                return Ok(ChainedPointer::NonPointer {
                    value: target.wrapping_sub(bias),
                    next,
                });
            }
            Ok(ChainedPointer::Rebase {
                target: u64::from(target),
                high8: 0,
                next,
            })
        }
        DYLD_CHAINED_PTR_32_CACHE => Ok(ChainedPointer::Rebase {
            target: bits(0, 30),
            high8: 0,
            next: scaled(bits(30, 2)),
        }),
        _ => Ok(ChainedPointer::Rebase {
            target: bits(0, 26),
            high8: 0,
            next: scaled(bits(26, 6)),
        }),
    }
}
