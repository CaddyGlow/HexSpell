//! Streaming PE directory inspection and optional RVA lookup indexing.
//!
//! Iterators yield errors once, then stop. Names borrow file bytes when UTF-8 is
//! valid; import names retain the owned parser's lossy decoding policy.

use super::{
    debug::DebugDirectoryEntry,
    export::ExportDirectory,
    header::PEType,
    import::{self, ImageImportDescriptor, ThunkSlot},
    relocation::{BaseRelocationBlock, BaseRelocationEntry},
    section::PeSection,
};
use crate::{
    errors::FileParseError,
    field::Field,
    utils::{extract_u16, extract_u32, extract_u64},
};
use alloc::borrow::Cow;
use alloc::vec::Vec;

fn extent(
    bytes: &[u8],
    start: usize,
    count: usize,
    stride: usize,
) -> Result<usize, FileParseError> {
    let end = count
        .checked_mul(stride)
        .and_then(|n| start.checked_add(n))
        .ok_or(FileParseError::BufferOverflow)?;
    bytes
        .get(start..end)
        .ok_or(FileParseError::BufferOverflow)?;
    Ok(end)
}

fn name(bytes: &[u8], offset: usize) -> Result<Cow<'_, str>, FileParseError> {
    crate::strings::read_c_string_ref(bytes, offset)
}

fn strict_name(bytes: &[u8], offset: usize) -> Result<&str, FileParseError> {
    core::str::from_utf8(crate::strings::read_c_bytes(bytes, offset)?)
        .map_err(|_| FileParseError::InvalidFileFormat)
}

macro_rules! streaming {
    ($typ:ident, $item:ty) => {
        impl<'a> Iterator for $typ<'a> {
            type Item = Result<$item, FileParseError>;
            fn next(&mut self) -> Option<Self::Item> {
                if self.done {
                    return None;
                }
                match self.read_next() {
                    Ok(Some(item)) => Some(Ok(item)),
                    Ok(None) => {
                        self.done = true;
                        None
                    }
                    Err(error) => {
                        self.done = true;
                        Some(Err(error))
                    }
                }
            }
        }
        impl core::iter::FusedIterator for $typ<'_> {}
    };
}

/// Optional index over immutable file-backed section ranges.
///
/// Non-overlapping ranges use binary search. Overlapping ranges fall back to
/// file-order lookup so results match `PE::rva_to_offset`.
pub struct RvaIndex<'a> {
    bytes: &'a [u8],
    sections: &'a [PeSection],
    sorted: Vec<usize>,
    overlapping: bool,
}

impl<'a> RvaIndex<'a> {
    /// Builds an index, retaining borrows so edits cannot silently invalidate it.
    pub fn new(bytes: &'a [u8], sections: &'a [PeSection]) -> Self {
        let mut sorted = Vec::with_capacity(sections.len());
        sorted.extend((0..sections.len()).filter(|&i| sections[i].size_of_raw_data.value != 0));
        sorted.sort_unstable_by_key(|&i| sections[i].virtual_address.value);
        let overlapping = sorted.windows(2).any(|pair| {
            let left = &sections[pair[0]];
            left.virtual_address
                .value
                .saturating_add(left.size_of_raw_data.value)
                > sections[pair[1]].virtual_address.value
        });
        Self {
            bytes,
            sections,
            sorted,
            overlapping,
        }
    }

    /// Translates an RVA with the same file-backed and header rules as the linear mapper.
    pub fn rva_to_offset(&self, rva: u32) -> Result<usize, FileParseError> {
        if rva == 0
            || self.overlapping
            || self
                .sections
                .first()
                .is_some_and(|s| rva < s.virtual_address.value)
        {
            return import::rva_to_offset(self.bytes, self.sections, rva);
        }
        let end = self
            .sorted
            .partition_point(|&i| self.sections[i].virtual_address.value <= rva);
        if end == 0 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let section = &self.sections[self.sorted[end - 1]];
        if rva
            >= section
                .virtual_address
                .value
                .saturating_add(section.size_of_raw_data.value)
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        let offset = (section.pointer_to_raw_data.value as usize)
            .checked_add((rva - section.virtual_address.value) as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        if offset >= self.bytes.len() {
            return Err(FileParseError::BufferOverflow);
        }
        Ok(offset)
    }
}

#[derive(Clone, Copy)]
struct Mapper<'a> {
    bytes: &'a [u8],
    sections: &'a [PeSection],
    index: Option<&'a RvaIndex<'a>>,
}

impl Mapper<'_> {
    fn offset(&self, rva: u32) -> Result<usize, FileParseError> {
        match self.index {
            Some(index) => index.rva_to_offset(rva),
            None => import::rva_to_offset(self.bytes, self.sections, rva),
        }
    }
    fn check_index(&self, index: &RvaIndex<'_>) -> Result<(), FileParseError> {
        if core::ptr::eq(self.bytes, index.bytes) && core::ptr::eq(self.sections, index.sections) {
            Ok(())
        } else {
            Err(FileParseError::InvalidFileFormat)
        }
    }
}

/// Imports from one DLL; descriptor metadata is stored once.
pub struct DllImportRef<'a> {
    /// Original descriptor fields.
    pub descriptor: ImageImportDescriptor,
    /// File offset of the DLL name.
    pub dll_name_offset: usize,
    /// Borrowed DLL name, or owned lossy decoding for invalid UTF-8.
    pub dll_name: Cow<'a, str>,
    /// Streaming ILT/IAT entries.
    pub entries: ImportEntries<'a>,
}

/// A resolved import with its original thunk and borrowed name.
pub enum ImportEntryRef<'a> {
    /// Import by ordinal.
    Ordinal { ordinal: u16, thunk: ThunkSlot },
    /// Import by name.
    ByName {
        hint: Field<u16>,
        name_offset: usize,
        name: Cow<'a, str>,
        thunk: ThunkSlot,
    },
}

/// Streaming import descriptors and DLL names.
pub struct Imports<'a> {
    map: Mapper<'a>,
    offset: usize,
    pe_type: PEType,
    done: bool,
}

impl<'a> Imports<'a> {
    /// Begins import inspection without collecting descriptors or thunks.
    pub fn new(
        bytes: &'a [u8],
        sections: &'a [PeSection],
        rva: u32,
        pe_type: PEType,
    ) -> Result<Self, FileParseError> {
        let map = Mapper {
            bytes,
            sections,
            index: None,
        };
        let offset = if rva == 0 { 0 } else { map.offset(rva)? };
        Ok(Self {
            map,
            offset,
            pe_type,
            done: rva == 0,
        })
    }

    /// Uses an index built for the same immutable buffer and section table.
    pub fn with_index(mut self, index: &'a RvaIndex<'a>) -> Result<Self, FileParseError> {
        self.map.check_index(index)?;
        self.map.index = Some(index);
        Ok(self)
    }

    fn read_next(&mut self) -> Result<Option<DllImportRef<'a>>, FileParseError> {
        extent(self.map.bytes, self.offset, 1, ImageImportDescriptor::SIZE)?;
        let descriptor = ImageImportDescriptor::parse(self.map.bytes, self.offset)?;
        if descriptor.is_null() {
            return Ok(None);
        }
        self.offset += ImageImportDescriptor::SIZE;
        let dll_name_offset = self.map.offset(descriptor.name.value)?;
        let dll_name = name(self.map.bytes, dll_name_offset)?;
        let rva = if descriptor.original_first_thunk.value != 0 {
            descriptor.original_first_thunk.value
        } else {
            descriptor.first_thunk.value
        };
        let offset = if rva == 0 { 0 } else { self.map.offset(rva)? };
        let entries = ImportEntries {
            map: self.map,
            offset,
            pe_type: self.pe_type,
            done: rva == 0,
        };
        Ok(Some(DllImportRef {
            descriptor,
            dll_name_offset,
            dll_name,
            entries,
        }))
    }
}
streaming!(Imports, DllImportRef<'a>);

/// Streaming import thunk entries.
pub struct ImportEntries<'a> {
    map: Mapper<'a>,
    offset: usize,
    pe_type: PEType,
    done: bool,
}

impl<'a> ImportEntries<'a> {
    fn read_next(&mut self) -> Result<Option<ImportEntryRef<'a>>, FileParseError> {
        let (raw, stride, flag) = match self.pe_type {
            PEType::PE32 => (
                u64::from(extract_u32(self.map.bytes, self.offset)?),
                4,
                1u64 << 31,
            ),
            PEType::PE32Plus => (extract_u64(self.map.bytes, self.offset)?, 8, 1u64 << 63),
        };
        if raw == 0 {
            return Ok(None);
        }
        let offset = self.offset;
        self.offset = offset
            .checked_add(stride)
            .ok_or(FileParseError::BufferOverflow)?;
        let thunk = if stride == 4 {
            ThunkSlot::U32(Field::new(raw as u32, offset, 4))
        } else {
            ThunkSlot::U64(Field::new(raw, offset, 8))
        };
        if raw & flag != 0 {
            return Ok(Some(ImportEntryRef::Ordinal {
                ordinal: raw as u16,
                thunk,
            }));
        }
        let rva = u32::try_from(raw).map_err(|_| FileParseError::ValueTooLarge)?;
        let offset = self.map.offset(rva)?;
        let hint = Field::new(extract_u16(self.map.bytes, offset)?, offset, 2);
        let name_offset = offset
            .checked_add(2)
            .ok_or(FileParseError::BufferOverflow)?;
        Ok(Some(ImportEntryRef::ByName {
            hint,
            name_offset,
            name: name(self.map.bytes, name_offset)?,
            thunk,
        }))
    }
}
streaming!(ImportEntries, ImportEntryRef<'a>);

/// A named export borrowing the original name bytes.
pub struct NamedExportRef<'a> {
    /// Borrowed UTF-8 export name.
    pub name: &'a str,
    /// Export ordinal.
    pub ordinal: u16,
    /// Original slot in the export address table.
    pub function_rva: Field<u32>,
    /// Original slot in the export name pointer table.
    pub name_rva: Field<u32>,
    /// Original slot in the export name ordinal table.
    pub name_ordinal_index: Field<u16>,
}

/// An export address table slot, including ordinal-only entries.
pub struct FunctionExportRef<'a> {
    /// Export ordinal.
    pub ordinal: u16,
    /// Position in the export address table.
    pub index: usize,
    /// Original slot in the export address table.
    pub function_rva: Field<u32>,
    /// Borrowed forwarder string, when this slot is a forwarder.
    pub forwarder: Option<&'a str>,
}

struct ExportTables<'a> {
    map: Mapper<'a>,
    directory: Option<ExportDirectory>,
    rva: u32,
    size: u32,
    functions: usize,
}

impl<'a> ExportTables<'a> {
    fn new(
        bytes: &'a [u8],
        sections: &'a [PeSection],
        rva: u32,
        size: u32,
    ) -> Result<Self, FileParseError> {
        let map = Mapper {
            bytes,
            sections,
            index: None,
        };
        let directory = if rva == 0 {
            None
        } else {
            let offset = map.offset(rva)?;
            extent(bytes, offset, 1, 40)?;
            Some(ExportDirectory::parse(bytes, offset)?)
        };
        let functions = match &directory {
            Some(d) if d.number_of_functions.value != 0 => {
                let offset = map.offset(d.address_of_functions.value)?;
                extent(bytes, offset, d.number_of_functions.value as usize, 4)?;
                offset
            }
            _ => 0,
        };
        Ok(Self {
            map,
            directory,
            rva,
            size,
            functions,
        })
    }
    fn ordinal(&self, index: u32) -> Result<u16, FileParseError> {
        self.directory
            .as_ref()
            .ok_or(FileParseError::InvalidFileFormat)?
            .base
            .value
            .checked_add(index)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or(FileParseError::ValueTooLarge)
    }
}

/// Streaming named export table rows.
pub struct Exports<'a> {
    tables: ExportTables<'a>,
    names: usize,
    ordinals: usize,
    current: usize,
    count: usize,
    done: bool,
}

impl<'a> Exports<'a> {
    /// Validates export table extents without collecting named entries.
    pub fn new(
        bytes: &'a [u8],
        sections: &'a [PeSection],
        rva: u32,
        size: u32,
    ) -> Result<Self, FileParseError> {
        let tables = ExportTables::new(bytes, sections, rva, size)?;
        let (count, names, ordinals) = match &tables.directory {
            Some(d) if d.number_of_names.value != 0 => {
                let count = d.number_of_names.value as usize;
                let names = tables.map.offset(d.address_of_names.value)?;
                let ordinals = tables.map.offset(d.address_of_name_ordinals.value)?;
                extent(bytes, names, count, 4)?;
                extent(bytes, ordinals, count, 2)?;
                (count, names, ordinals)
            }
            _ => (0, 0, 0),
        };
        Ok(Self {
            tables,
            names,
            ordinals,
            current: 0,
            count,
            done: false,
        })
    }

    /// Uses an index built for the same immutable buffer and section table.
    pub fn with_index(mut self, index: &'a RvaIndex<'a>) -> Result<Self, FileParseError> {
        self.tables.map.check_index(index)?;
        self.tables.map.index = Some(index);
        Ok(self)
    }

    fn read_next(&mut self) -> Result<Option<NamedExportRef<'a>>, FileParseError> {
        if self.current == self.count {
            return Ok(None);
        }
        let i = self.current;
        self.current += 1;
        let bytes = self.tables.map.bytes;
        let noff = self.names + i * 4;
        let ooff = self.ordinals + i * 2;
        let name_rva = Field::new(extract_u32(bytes, noff)?, noff, 4);
        let name_ordinal_index = Field::new(extract_u16(bytes, ooff)?, ooff, 2);
        if u32::from(name_ordinal_index.value)
            >= self
                .tables
                .directory
                .as_ref()
                .ok_or(FileParseError::InvalidFileFormat)?
                .number_of_functions
                .value
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        let foff = self.tables.functions + usize::from(name_ordinal_index.value) * 4;
        Ok(Some(NamedExportRef {
            name: strict_name(bytes, self.tables.map.offset(name_rva.value)?)?,
            ordinal: self.tables.ordinal(u32::from(name_ordinal_index.value))?,
            function_rva: Field::new(extract_u32(bytes, foff)?, foff, 4),
            name_rva,
            name_ordinal_index,
        }))
    }
}
streaming!(Exports, NamedExportRef<'a>);

/// Streaming export address table slots.
pub struct ExportFunctions<'a> {
    tables: ExportTables<'a>,
    current: usize,
    done: bool,
}

impl<'a> ExportFunctions<'a> {
    /// Validates the address table extent without collecting entries.
    pub fn new(
        bytes: &'a [u8],
        sections: &'a [PeSection],
        rva: u32,
        size: u32,
    ) -> Result<Self, FileParseError> {
        Ok(Self {
            tables: ExportTables::new(bytes, sections, rva, size)?,
            current: 0,
            done: false,
        })
    }

    /// Uses an index built for the same immutable buffer and section table.
    pub fn with_index(mut self, index: &'a RvaIndex<'a>) -> Result<Self, FileParseError> {
        self.tables.map.check_index(index)?;
        self.tables.map.index = Some(index);
        Ok(self)
    }

    fn read_next(&mut self) -> Result<Option<FunctionExportRef<'a>>, FileParseError> {
        let Some(d) = &self.tables.directory else {
            return Ok(None);
        };
        if self.current == d.number_of_functions.value as usize {
            return Ok(None);
        }
        let index = self.current;
        self.current += 1;
        let offset = self.tables.functions + index * 4;
        let function_rva = Field::new(extract_u32(self.tables.map.bytes, offset)?, offset, 4);
        let forwarder = if d.is_forwarder_rva(self.tables.rva, self.tables.size, function_rva.value)
        {
            Some(strict_name(
                self.tables.map.bytes,
                self.tables.map.offset(function_rva.value)?,
            )?)
        } else {
            None
        };
        Ok(Some(FunctionExportRef {
            ordinal: self.tables.ordinal(index as u32)?,
            index,
            function_rva,
            forwarder,
        }))
    }
}
streaming!(ExportFunctions, FunctionExportRef<'a>);

/// A borrowed relocation block, retaining its original header fields.
pub struct RelocationBlockRef<'a> {
    bytes: &'a [u8],
    start: usize,
    end: usize,
    /// Page RVA from the block header.
    pub page_rva: Field<u32>,
    /// Total block size from the block header.
    pub block_size: Field<u32>,
}

impl RelocationBlockRef<'_> {
    /// Iterates relocation words without allocating.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = BaseRelocationEntry> + '_ {
        self.bytes[self.start..self.end]
            .as_chunks::<2>()
            .0
            .iter()
            .enumerate()
            .map(|(i, raw)| BaseRelocationEntry {
                raw: Field::new(u16::from_le_bytes([raw[0], raw[1]]), self.start + i * 2, 2),
            })
    }

    /// Explicitly collects this block for callers that need editable metadata.
    pub fn to_owned(&self) -> BaseRelocationBlock {
        BaseRelocationBlock {
            page_rva: self.page_rva.clone(),
            block_size: self.block_size.clone(),
            entries: self.entries().collect(),
        }
    }
}

/// Streaming relocation blocks backed by the directory byte range.
pub struct Relocations<'a> {
    bytes: &'a [u8],
    offset: usize,
    end: usize,
    done: bool,
}

impl<'a> Relocations<'a> {
    /// Validates the directory extent; each block is checked when visited.
    pub fn new(bytes: &'a [u8], offset: usize, size: usize) -> Result<Self, FileParseError> {
        let end = extent(bytes, offset, size, 1)?;
        Ok(Self {
            bytes,
            offset,
            end,
            done: false,
        })
    }

    fn read_next(&mut self) -> Result<Option<RelocationBlockRef<'a>>, FileParseError> {
        if self.offset == self.end {
            return Ok(None);
        }
        if self.end - self.offset < 8 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let offset = self.offset;
        let page_rva = Field::new(extract_u32(self.bytes, offset)?, offset, 4);
        let size = extract_u32(self.bytes, offset + 4)?;
        if size < 8 || size % 2 != 0 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let next = offset
            .checked_add(size as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        if next > self.end {
            return Err(FileParseError::BufferOverflow);
        }
        self.offset = next;
        Ok(Some(RelocationBlockRef {
            bytes: self.bytes,
            start: offset + 8,
            end: next,
            page_rva,
            block_size: Field::new(size, offset + 4, 4),
        }))
    }
}
streaming!(Relocations, RelocationBlockRef<'a>);

/// Streaming fixed-size debug directory records.
pub struct DebugEntries<'a> {
    bytes: &'a [u8],
    offset: usize,
    end: usize,
    done: bool,
}

impl<'a> DebugEntries<'a> {
    /// Validates the directory extent and fixed record size.
    pub fn new(bytes: &'a [u8], offset: usize, size: usize) -> Result<Self, FileParseError> {
        if !size.is_multiple_of(DebugDirectoryEntry::SIZE) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let end = extent(bytes, offset, size, 1)?;
        Ok(Self {
            bytes,
            offset,
            end,
            done: false,
        })
    }

    fn read_next(&mut self) -> Result<Option<DebugDirectoryEntry>, FileParseError> {
        if self.offset == self.end {
            return Ok(None);
        }
        let record = DebugDirectoryEntry::parse(self.bytes, self.offset)?;
        self.offset += DebugDirectoryEntry::SIZE;
        Ok(Some(record))
    }
}
streaming!(DebugEntries, DebugDirectoryEntry);
