//! Convert a contiguous RVA-addressed memory image into a file-layout PE.
//!
//! Enabled by `pe` and `pe-reconstruct`; works with `no_std + alloc`.

use alloc::vec::Vec;

use super::{debug::DebugDirectory, header, section, view::PeHeaders, PE};
use crate::errors::FileParseError;

fn align(value: u32, alignment: u32) -> Result<u32, FileParseError> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(FileParseError::ValueTooLarge)
}

struct SectionCopy {
    rva: u32,
    length: u32,
    offset: u32,
    raw_size: u32,
}

impl PE {
    /// Reconstructs a file-layout PE from bytes starting at the loaded image base.
    ///
    /// Input offset `rva` must contain the bytes mapped at that RVA, including
    /// readable headers. Sections are packed in section-table order at
    /// `FileAlignment` boundaries. Copies `VirtualSize` bytes per section (or
    /// `SizeOfRawData` when `VirtualSize` is zero), with zero-filled file padding.
    /// Runtime changes and zero-fill sections are captured; materialized
    /// uninitialized-data sections become initialized-data sections.
    ///
    /// Preserves RVAs and ImageBase, recomputes size totals and checksum, and
    /// remaps mapped debug payload pointers. Clears certificates, COFF symbols,
    /// section relocation/line-number references, and file-only debug payload
    /// references. Overlays and original file padding cannot be recovered.
    ///
    /// This only converts layout: it does not undo loader relocations, rebuild
    /// imports overwritten by the loader, or guarantee a runnable executable.
    /// The caller must supply a consistent snapshot; no process memory is read.
    ///
    /// Returns an error for missing bytes, overlapping sections, malformed
    /// headers/debug records, invalid alignments, or overflowing extents.
    /// Section alignments below 4096 are currently unsupported.
    pub fn from_memory_image(memory: &[u8]) -> Result<Self, FileParseError> {
        let headers = PeHeaders::parse(memory)?;
        let mut source = PE::from_slice(memory)?;
        let optional = &source.optional_header;
        // The general parser can inspect bytes past a short declared optional
        // header. Reconstruction must not write those fields over section data.
        let required_optional =
            headers.directory_offset()? + optional.active_data_directory_count() * 8;
        if required_optional > source.coff_header.size_of_optional_header.value as usize {
            return Err(FileParseError::InvalidFileFormat);
        }
        let file_alignment = optional.file_alignment.value;
        let section_alignment = optional.section_alignment.value;
        if !file_alignment.is_power_of_two()
            || !section_alignment.is_power_of_two()
            || file_alignment > section_alignment
            || !(512..=65536).contains(&file_alignment)
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        if section_alignment < 4096 {
            return Err(FileParseError::UnsupportedFeature(
                "memory reconstruction with SectionAlignment below 4096".into(),
            ));
        }
        let table_end = headers
            .sections
            .checked_add(source.sections.len() * 40)
            .ok_or(FileParseError::BufferOverflow)?;
        let original_headers = optional.size_of_headers.value;
        if (original_headers as usize) < table_end {
            return Err(FileParseError::InvalidFileFormat);
        }
        let header_bytes = memory
            .get(..original_headers as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        let size_of_headers = align(original_headers, file_alignment)?;
        let mut size_of_image = align(size_of_headers, section_alignment)?;
        let mut file_end = size_of_headers;
        let mut copies = Vec::with_capacity(source.sections.len());
        let mut ranges = Vec::with_capacity(source.sections.len());
        for section in &source.sections {
            let rva = section.virtual_address.value;
            let length = if section.virtual_size.value == 0 {
                section.size_of_raw_data.value
            } else {
                section.virtual_size.value
            };
            let raw_size = align(length, file_alignment)?;
            let offset = if length == 0 { 0 } else { file_end };
            if length != 0 {
                let end = rva
                    .checked_add(length)
                    .ok_or(FileParseError::ValueTooLarge)?;
                memory
                    .get(rva as usize..end as usize)
                    .ok_or(FileParseError::BufferOverflow)?;
                if rva < size_of_headers || !rva.is_multiple_of(section_alignment) {
                    return Err(FileParseError::InvalidFileFormat);
                }
                let mapped_end = rva
                    .checked_add(raw_size)
                    .ok_or(FileParseError::ValueTooLarge)?;
                ranges.push((rva, mapped_end));
                size_of_image = size_of_image.max(align(mapped_end, section_alignment)?);
                file_end = file_end
                    .checked_add(raw_size)
                    .ok_or(FileParseError::ValueTooLarge)?;
            }
            copies.push(SectionCopy {
                rva,
                length,
                offset,
                raw_size,
            });
        }
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(file_end as usize)
            .map_err(|_| FileParseError::ValueTooLarge)?;
        buffer.resize(file_end as usize, 0);
        buffer[..header_bytes.len()].copy_from_slice(header_bytes);
        let mut code_size = 0u32;
        let mut data_size = 0u32;
        for (section, copy) in source.sections.iter_mut().zip(&copies) {
            if copy.length != 0 {
                buffer[copy.offset as usize..(copy.offset + copy.length) as usize]
                    .copy_from_slice(&memory[copy.rva as usize..(copy.rva + copy.length) as usize]);
            }
            section
                .pointer_to_raw_data
                .update(&mut buffer, copy.offset)?;
            section
                .size_of_raw_data
                .update(&mut buffer, copy.raw_size)?;
            section.pointer_to_relocations.update(&mut buffer, 0)?;
            section.number_of_relocations.update(&mut buffer, 0)?;
            section.pointer_to_linenumbers.update(&mut buffer, 0)?;
            section.number_of_linenumbers.update(&mut buffer, 0)?;
            let mut flags = section.characteristics.value;
            if flags & 0x80 != 0 && copy.length != 0 {
                flags = (flags & !0x80) | section::INITIALIZED_DATA;
                section.characteristics.update(&mut buffer, flags)?;
            }
            if flags & section::CODE != 0 {
                code_size = code_size
                    .checked_add(copy.raw_size)
                    .ok_or(FileParseError::ValueTooLarge)?;
            }
            if flags & section::INITIALIZED_DATA != 0 {
                data_size = data_size
                    .checked_add(copy.raw_size)
                    .ok_or(FileParseError::ValueTooLarge)?;
            }
        }
        source
            .coff_header
            .pointer_to_symbol_table
            .update(&mut buffer, 0)?;
        source
            .coff_header
            .number_of_symbols
            .update(&mut buffer, 0)?;
        let optional = &mut source.optional_header;
        optional
            .size_of_headers
            .update(&mut buffer, size_of_headers)?;
        optional.size_of_image.update(&mut buffer, size_of_image)?;
        optional.size_of_code.update(&mut buffer, code_size)?;
        optional
            .size_of_initialized_data
            .update(&mut buffer, data_size)?;
        optional.size_of_uninitialized_data.update(&mut buffer, 0)?;
        if optional.has_data_directory(header::SECURITY) {
            let security = &mut optional.data_directories[header::SECURITY];
            security.virtual_address.update(&mut buffer, 0)?;
            security.size.update(&mut buffer, 0)?;
        }
        let mut pe = PE::from_buffer(buffer)?;
        fix_debug_pointers(&mut pe, &copies, original_headers)?;
        pe.optional_header.checksum.update(&mut pe.buffer, 0)?;
        let checksum = pe.calc_checksum();
        pe.optional_header
            .checksum
            .update(&mut pe.buffer, checksum)?;
        Ok(pe)
    }
}

fn mapped_range(
    copies: &[SectionCopy],
    headers: u32,
    rva: u32,
    size: u32,
) -> Result<usize, FileParseError> {
    let end = rva.checked_add(size).ok_or(FileParseError::ValueTooLarge)?;
    if end <= headers {
        return Ok(rva as usize);
    }
    for copy in copies {
        if copy.length != 0
            && rva >= copy.rva
            && end
                <= copy
                    .rva
                    .checked_add(copy.length)
                    .ok_or(FileParseError::ValueTooLarge)?
        {
            return Ok((copy.offset + (rva - copy.rva)) as usize);
        }
    }
    Err(FileParseError::InvalidFileFormat)
}

fn fix_debug_pointers(
    pe: &mut PE,
    copies: &[SectionCopy],
    headers: u32,
) -> Result<(), FileParseError> {
    if !pe.optional_header.has_data_directory(header::DEBUG) {
        return Ok(());
    }
    let directory = &pe.optional_header.data_directories[header::DEBUG];
    let rva = directory.virtual_address.value;
    let size = directory.size.value;
    if rva == 0 && size == 0 {
        return Ok(());
    }
    if rva == 0 || size == 0 {
        return Err(FileParseError::InvalidFileFormat);
    }
    // Rewriting debug records must never overwrite reconstructed header fields.
    if rva < pe.optional_header.size_of_headers.value {
        return Err(FileParseError::InvalidFileFormat);
    }
    let offset = mapped_range(copies, headers, rva, size)?;
    let debug = DebugDirectory::parse(&pe.buffer, offset, size as usize)?;
    for mut entry in debug.entries {
        if entry.address_of_raw_data.value == 0 || entry.size_of_data.value == 0 {
            entry.pointer_to_raw_data.update(&mut pe.buffer, 0)?;
            entry.address_of_raw_data.update(&mut pe.buffer, 0)?;
            entry.size_of_data.update(&mut pe.buffer, 0)?;
        } else {
            let offset = mapped_range(
                copies,
                headers,
                entry.address_of_raw_data.value,
                entry.size_of_data.value,
            )?;
            entry
                .pointer_to_raw_data
                .update(&mut pe.buffer, offset as u32)?;
        }
    }
    Ok(())
}
