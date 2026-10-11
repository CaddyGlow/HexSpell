use super::ResourceDirectoryOwned;
use crate::{
    errors::FileParseError,
    pe::{header, layout::FileOffsetFixups, section, PE},
};
use alloc::string::String;
/// Explicit treatment of a preexisting Authenticode certificate table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignaturePolicy {
    PreserveBytes,
    Strip,
}
/// Signature state after editing. Editing does not generate signatures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureOutcome {
    Unsigned,
    Invalidated,
    Stripped,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceEditReport {
    pub section_rva: u32,
    pub size: u32,
    pub signature: SignatureOutcome,
}
impl PE {
    /// Imports a lossless resource model from this image.
    pub fn owned_resources(&self) -> Result<ResourceDirectoryOwned, FileParseError> {
        ResourceDirectoryOwned::from_pe(self)
    }
    /// Appends a resource section transactionally. Existing section RVAs remain unchanged.
    pub fn replace_resources(
        &mut self,
        resources: &ResourceDirectoryOwned,
        policy: SignaturePolicy,
    ) -> Result<ResourceEditReport, FileParseError> {
        preflight(self)?;
        let mut candidate = PE::from_buffer(self.buffer.clone())?;
        let mut signature = SignatureOutcome::Unsigned;
        if candidate
            .optional_header
            .has_data_directory(header::SECURITY)
        {
            let security = &candidate.optional_header.data_directories[header::SECURITY];
            let start = security.virtual_address.value as usize;
            let size = security.size.value as usize;
            if start != 0 || size != 0 {
                if start == 0 || size == 0 {
                    return Err(FileParseError::InvalidFileFormat);
                }
                let end = start
                    .checked_add(size)
                    .ok_or(FileParseError::ValueTooLarge)?;
                if end > candidate.buffer.len() || !start.is_multiple_of(8) {
                    return Err(FileParseError::InvalidFileFormat);
                }
                let raw_end = candidate
                    .sections
                    .iter()
                    .filter(|s| s.size_of_raw_data.value > 0)
                    .map(|s| {
                        s.pointer_to_raw_data.value as usize + s.size_of_raw_data.value as usize
                    })
                    .max()
                    .unwrap_or(0)
                    .max(candidate.optional_header.size_of_headers.value as usize);
                if start < raw_end {
                    return Err(FileParseError::InvalidFileFormat);
                }
                signature = SignatureOutcome::Invalidated;
                if policy == SignaturePolicy::Strip {
                    let overlaps = |pointer: u32, length: usize| {
                        let p = pointer as usize;
                        pointer != 0
                            && p < end
                            && p.checked_add(length.max(1)).is_none_or(|e| e > start)
                    };
                    let symbol_start = candidate.coff_header.pointer_to_symbol_table.value;
                    let mut symbol_size = (candidate.coff_header.number_of_symbols.value as usize)
                        .checked_mul(18)
                        .ok_or(FileParseError::ValueTooLarge)?;
                    if symbol_start != 0 {
                        let strings = (symbol_start as usize)
                            .checked_add(symbol_size)
                            .ok_or(FileParseError::ValueTooLarge)?;
                        let string_size =
                            crate::utils::extract_u32(&candidate.buffer, strings)? as usize;
                        if string_size < 4 {
                            return Err(FileParseError::InvalidFileFormat);
                        }
                        symbol_size = symbol_size
                            .checked_add(string_size)
                            .ok_or(FileParseError::ValueTooLarge)?;
                        if (symbol_start as usize)
                            .checked_add(symbol_size)
                            .is_none_or(|n| n > candidate.buffer.len())
                        {
                            return Err(FileParseError::BufferOverflow);
                        }
                    }
                    if overlaps(symbol_start, symbol_size) {
                        return Err(FileParseError::InvalidFileFormat);
                    }
                    for section in &candidate.sections {
                        if overlaps(
                            section.pointer_to_relocations.value,
                            section.number_of_relocations.value as usize * 10,
                        ) || overlaps(
                            section.pointer_to_linenumbers.value,
                            section.number_of_linenumbers.value as usize * 6,
                        ) {
                            return Err(FileParseError::InvalidFileFormat);
                        }
                    }
                    if let Some(debug) = candidate.debug_directory()? {
                        for entry in debug.entries {
                            if overlaps(
                                entry.pointer_to_raw_data.value,
                                entry.size_of_data.value as usize,
                            ) {
                                return Err(FileParseError::InvalidFileFormat);
                            }
                        }
                    }
                    let mut pos = start;
                    while pos < end {
                        let len = crate::utils::extract_u32(&candidate.buffer, pos)? as usize;
                        if len < 8 || pos.checked_add(len).is_none_or(|n| n > end) {
                            return Err(FileParseError::InvalidFileFormat);
                        }
                        pos = pos
                            .checked_add((len + 7) & !7)
                            .ok_or(FileParseError::ValueTooLarge)?;
                    }
                    if pos != end {
                        return Err(FileParseError::InvalidFileFormat);
                    }
                    let fixups = FileOffsetFixups::capture(&candidate)?;
                    candidate.buffer.drain(start..end);
                    fixups.apply(&mut candidate.buffer, &[(start, size, 0)])?;
                    let security =
                        &mut candidate.optional_header.data_directories[header::SECURITY];
                    security.virtual_address.update(&mut candidate.buffer, 0)?;
                    security.size.update(&mut candidate.buffer, 0)?;
                    candidate = PE::from_buffer(candidate.buffer)?;
                    signature = SignatureOutcome::Stripped;
                }
            }
        }
        if !candidate
            .optional_header
            .has_data_directory(header::RESOURCE)
        {
            let base = if candidate.optional_header.magic.value == 0x20b {
                112
            } else {
                96
            };
            let required = base + (header::RESOURCE + 1) * 8;
            let old = candidate.coff_header.size_of_optional_header.value as usize;
            if old < required {
                candidate.grow_optional_header(
                    u16::try_from(required - old).map_err(|_| FileParseError::ValueTooLarge)?,
                )?;
            }
            candidate
                .optional_header
                .number_of_rva_and_sizes
                .update(&mut candidate.buffer, (header::RESOURCE + 1) as u32)?;
            candidate = PE::from_buffer(candidate.buffer)?;
        }
        let header_end = candidate
            .sections
            .last()
            .ok_or(FileParseError::InvalidFileFormat)?
            .characteristics
            .offset
            .checked_add(44)
            .ok_or(FileParseError::ValueTooLarge)?;
        let fa = candidate.optional_header.file_alignment.value as usize;
        let header_size = header_end
            .checked_add(fa - 1)
            .map(|n| n & !(fa - 1))
            .ok_or(FileParseError::ValueTooLarge)?;
        if candidate
            .sections
            .iter()
            .any(|s| (s.virtual_address.value as usize) < header_size)
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        let measured = resources.serialize(0)?;
        let size = u32::try_from(measured.len()).map_err(|_| FileParseError::ValueTooLarge)?;
        let last = candidate
            .sections
            .last()
            .ok_or(FileParseError::InvalidFileFormat)?;
        let align = candidate.optional_header.section_alignment.value;
        let rva = last
            .virtual_address
            .value
            .checked_add(last.virtual_size.value.max(last.size_of_raw_data.value))
            .and_then(|n| n.checked_add(align - 1))
            .map(|n| n & !(align - 1))
            .ok_or(FileParseError::ValueTooLarge)?;
        let payload = resources.serialize(rva)?;
        let section = candidate.insert_section(section::NewSection {
            name: String::from(".rsrc"),
            data: payload,
            characteristics: section::READ | section::INITIALIZED_DATA,
        })?;
        if section.virtual_address.value != rva {
            return Err(FileParseError::InvalidFileFormat);
        }
        let directory = &mut candidate.optional_header.data_directories[header::RESOURCE];
        directory
            .virtual_address
            .update(&mut candidate.buffer, rva)?;
        directory.size.update(&mut candidate.buffer, size)?;
        let initialized = candidate
            .sections
            .iter()
            .filter(|s| s.characteristics.value & section::INITIALIZED_DATA != 0)
            .try_fold(0u32, |n, s| {
                n.checked_add(s.size_of_raw_data.value)
                    .ok_or(FileParseError::ValueTooLarge)
            })?;
        candidate
            .optional_header
            .size_of_initialized_data
            .update(&mut candidate.buffer, initialized)?;
        candidate.sync_layout()?;
        // Validate the emitted bytes, rather than cached fields from before the edits.
        candidate = PE::from_buffer(candidate.buffer)?;
        let imported = candidate.owned_resources()?;
        if imported.serialize(rva)? != resources.serialize(rva)? {
            return Err(FileParseError::InvalidFileFormat);
        }
        let report = ResourceEditReport {
            section_rva: rva,
            size,
            signature,
        };
        *self = candidate;
        Ok(report)
    }
}
fn preflight(pe: &PE) -> Result<(), FileParseError> {
    let directory_base = if pe.optional_header.magic.value == 0x20b {
        112
    } else {
        96
    };
    // The parser can expose directory fields beyond SizeOfOptionalHeader.
    // Such fields alias the section table and must never be edited as directories.
    let required = directory_base + pe.optional_header.active_data_directory_count() * 8;
    if (pe.coff_header.size_of_optional_header.value as usize) < required {
        return Err(FileParseError::InvalidFileFormat);
    }
    let fa = pe.optional_header.file_alignment.value;
    let sa = pe.optional_header.section_alignment.value;
    if !fa.is_power_of_two()
        || !sa.is_power_of_two()
        || fa < 512
        || sa < 4096
        || sa < fa
        || pe.sections.is_empty()
        || pe.sections.len() >= 96
    {
        return Err(FileParseError::InvalidFileFormat);
    }
    let mut raw_end = pe.optional_header.size_of_headers.value;
    let mut virtual_end = 0;
    for s in &pe.sections {
        let raw = s.pointer_to_raw_data.value;
        let rva = s.virtual_address.value;
        if s.size_of_raw_data.value > 0 && (raw < raw_end || raw % fa != 0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        if rva < virtual_end || rva % sa != 0 {
            return Err(FileParseError::InvalidFileFormat);
        }
        if s.size_of_raw_data.value > 0 {
            raw_end = raw
                .checked_add(s.size_of_raw_data.value)
                .ok_or(FileParseError::ValueTooLarge)?;
        }
        virtual_end = rva
            .checked_add(s.virtual_size.value.max(s.size_of_raw_data.value))
            .ok_or(FileParseError::ValueTooLarge)?;
        if raw_end as usize > pe.buffer.len() {
            return Err(FileParseError::BufferOverflow);
        }
    }
    Ok(())
}
