//! Dyld bind/export blob decoding (`LC_DYLD_INFO`, `LC_DYLD_EXPORTS_TRIE`).
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

/// An uncompressed chained import (DYLD_CHAINED_IMPORT).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainedImport {
    /// Signed dependency ordinal (positive values are one-based).
    pub library_ordinal: i8,
    /// Whether missing symbols are permitted.
    pub weak: bool,
    /// Imported symbol name.
    pub name: String,
}
/// Starts for a scoped ordinary 64-bit chain. Authenticated formats are rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainedSegment {
    /// Zero-based load-command segment index.
    pub segment_index: usize,
    /// Page size (4096 or 16384).
    pub page_size: u16,
    /// Preferred virtual offset from the Mach header mapping.
    pub segment_offset: u64,
    /// First chain byte offset for each page; None denotes no chain.
    pub page_starts: Vec<Option<u16>>,
}
/// Parsed DYLD_CHAINED_PTR_64_OFFSET metadata. Pointer words remain in mapped segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainedFixups {
    /// Imported symbol records in pointer ordinal order.
    pub imports: Vec<ChainedImport>,
    /// Segments containing runtime pointer chains.
    pub segments: Vec<ChainedSegment>,
}
/// Decodes the macOS writer profile: version zero, uncompressed imports and 64-bit offset pointers.
/// Other import encodings, authenticated pointers and multi-start pages are explicitly unsupported.
/// Copied names (including their terminators) and decoded page entries share an
/// eight-times-input-size budget. Excessive alias expansion returns `ValueTooLarge`.
pub fn decode_chained_fixups(data: &[u8]) -> Result<ChainedFixups, FileParseError> {
    fn word(data: &[u8], offset: usize) -> Result<u32, FileParseError> {
        Ok(u32::from_le_bytes(
            data.get(
                offset
                    ..offset
                        .checked_add(4)
                        .ok_or(FileParseError::BufferOverflow)?,
            )
            .ok_or(FileParseError::BufferOverflow)?
            .try_into()
            .map_err(|_| FileParseError::BufferOverflow)?,
        ))
    }
    fn half(data: &[u8], offset: usize) -> Result<u16, FileParseError> {
        Ok(u16::from_le_bytes(
            data.get(
                offset
                    ..offset
                        .checked_add(2)
                        .ok_or(FileParseError::BufferOverflow)?,
            )
            .ok_or(FileParseError::BufferOverflow)?
            .try_into()
            .map_err(|_| FileParseError::BufferOverflow)?,
        ))
    }
    if word(data, 0)? != 0 || word(data, 20)? != 1 || word(data, 24)? != 0 {
        return Err(FileParseError::UnsupportedFeature(String::from(
            "chained fixup encoding",
        )));
    }
    // Count bounds alone do not bound allocation: imports can share a long name,
    // and many segment records can alias the same page-start array.
    let mut remaining = data.len().saturating_mul(8);
    let imports_offset = word(data, 8)? as usize;
    let symbols_offset = word(data, 12)? as usize;
    let count = word(data, 16)? as usize;
    if count > data.len() / 4 {
        return Err(FileParseError::BufferOverflow);
    }
    let imports_end = count
        .checked_mul(4)
        .and_then(|size| imports_offset.checked_add(size))
        .ok_or(FileParseError::BufferOverflow)?;
    data.get(imports_offset..imports_end)
        .ok_or(FileParseError::BufferOverflow)?;
    let mut imports = Vec::new();
    for i in 0..count {
        let raw = word(
            data,
            imports_offset
                .checked_add(i * 4)
                .ok_or(FileParseError::BufferOverflow)?,
        )?;
        let offset = symbols_offset
            .checked_add((raw >> 9) as usize)
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
            library_ordinal: raw as i8,
            weak: raw & 256 != 0,
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
        if !matches!(page_size, 4096 | 16384) || half(segment_data, 6)? != 6 {
            return Err(FileParseError::UnsupportedFeature(String::from(
                "chained pointer format",
            )));
        }
        let segment_offset = u64::from_le_bytes(
            segment_data
                .get(8..16)
                .ok_or(FileParseError::BufferOverflow)?
                .try_into()
                .map_err(|_| FileParseError::BufferOverflow)?,
        );
        let pages = half(segment_data, 20)?;
        segment_data
            .get(22..22 + usize::from(pages) * 2)
            .ok_or(FileParseError::BufferOverflow)?;
        remaining = remaining
            .checked_sub(usize::from(pages) * core::mem::size_of::<Option<u16>>())
            .ok_or(FileParseError::ValueTooLarge)?;
        let mut page_starts = Vec::new();
        for p in 0..usize::from(pages) {
            let start = half(segment_data, 22 + p * 2)?;
            if start == 0xffff {
                page_starts.push(None);
            } else if start & 0x8000 != 0 {
                return Err(FileParseError::UnsupportedFeature(String::from(
                    "multiple chained starts",
                )));
            } else if start >= page_size || start & 3 != 0 {
                return Err(FileParseError::InvalidFileFormat);
            } else {
                page_starts.push(Some(start));
            }
        }
        segments.push(ChainedSegment {
            segment_index: i,
            page_size,
            segment_offset,
            page_starts,
        });
    }
    Ok(ChainedFixups { imports, segments })
}

impl<B: core::ops::Deref<Target = [u8]>> super::MachO<B> {
    /// Lazily decodes modern chained-fixup metadata for the supported ordinary 64-bit profile.
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
}

/// One DYLD_CHAINED_PTR_64_OFFSET word. `next` is a byte distance within its page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainedPointer {
    /// Bind to an import-table ordinal with an unsigned embedded addend.
    Bind {
        /// Zero-based chained import index.
        ordinal: u32,
        /// Unsigned embedded pointer addend.
        addend: u8,
        /// Distance to next pointer, or zero to end the chain.
        next: u16,
    },
    /// Rebase an image-relative target; high8 reconstructs the top address bits.
    Rebase {
        /// Image-relative target offset.
        target: u64,
        /// Top eight bits of the unslid pointer.
        high8: u8,
        /// Distance to next pointer, or zero to end the chain.
        next: u16,
    },
}
/// Decodes one ordinary 64-bit offset chain word, rejecting nonzero reserved bits.
pub fn decode_chained_pointer(word: u64) -> Result<ChainedPointer, FileParseError> {
    let next = (((word >> 51) & 0xfff) * 4) as u16;
    if word >> 63 != 0 {
        if word & (0x7ffffu64 << 32) != 0 {
            return Err(FileParseError::InvalidFileFormat);
        }
        Ok(ChainedPointer::Bind {
            ordinal: (word & 0xffffff) as u32,
            addend: (word >> 24) as u8,
            next,
        })
    } else {
        if word & (0x7fu64 << 44) != 0 {
            return Err(FileParseError::InvalidFileFormat);
        }
        Ok(ChainedPointer::Rebase {
            target: word & 0xfffffffff,
            high8: (word >> 36) as u8,
            next,
        })
    }
}
