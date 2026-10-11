//! Minimal write/layout planning helpers (P2).
//!
//! Structural edits (`insert_section`, `insert_segment`, …) mutate the buffer immediately. These
//! helpers compute the resulting layout **before** applying changes so callers can preview growth
//! or bail out early.

#[cfg(feature = "pe")]
use crate::errors::FileParseError;
#[cfg(feature = "pe")]
use crate::pe::section::NewSection;
#[cfg(feature = "pe")]
use crate::pe::PE;

/// Planned outcome of appending a PE section (mirrors [`PE::insert_section`] sizing rules).
#[cfg(feature = "pe")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeInsertSectionPlan {
    /// New section header offset in the file.
    pub section_header_offset: usize,
    /// RVA of the new section.
    pub virtual_address: u32,
    /// File offset of raw section data.
    pub raw_data_offset: u32,
    /// Padded raw size on disk.
    pub size_of_raw_data: u32,
    /// Total buffer length after the insert.
    pub new_buffer_len: usize,
}

/// Computes where a new PE section would be placed without mutating `pe`.
#[cfg(feature = "pe")]
pub fn plan_pe_insert_section<B: core::ops::Deref<Target = [u8]>>(
    pe: &PE<B>,
    new: &NewSection,
) -> Result<PeInsertSectionPlan, FileParseError> {
    let file_alignment = pe.optional_header.file_alignment.value;
    let section_alignment = pe.optional_header.section_alignment.value;
    if !file_alignment.is_power_of_two() || !section_alignment.is_power_of_two() {
        return Err(FileParseError::InvalidFileFormat);
    }
    let align = |value: u32, alignment: u32| {
        value
            .checked_add(alignment - 1)
            .map(|value| value & !(alignment - 1))
            .ok_or(FileParseError::ValueTooLarge)
    };

    let last_section = pe
        .sections
        .last()
        .ok_or(FileParseError::InvalidFileFormat)?;

    let section_header_offset = last_section
        .characteristics
        .offset
        .checked_add(last_section.characteristics.size)
        .ok_or(FileParseError::BufferOverflow)?;
    let mut virtual_end = pe.optional_header.size_of_headers.value;
    let mut raw_end = pe.optional_header.size_of_headers.value;
    for section in &pe.sections {
        virtual_end = virtual_end.max(
            section
                .virtual_address
                .value
                .checked_add(
                    section
                        .virtual_size
                        .value
                        .max(section.size_of_raw_data.value),
                )
                .ok_or(FileParseError::ValueTooLarge)?,
        );
        if section.size_of_raw_data.value != 0 {
            raw_end = raw_end.max(
                section
                    .pointer_to_raw_data
                    .value
                    .checked_add(section.size_of_raw_data.value)
                    .ok_or(FileParseError::ValueTooLarge)?,
            );
        }
    }
    let virtual_address = align(virtual_end, section_alignment)?;
    let virtual_size = align(
        u32::try_from(new.data.len()).map_err(|_| FileParseError::ValueTooLarge)?,
        section_alignment,
    )?;
    align(
        virtual_address
            .checked_add(virtual_size)
            .ok_or(FileParseError::ValueTooLarge)?,
        section_alignment,
    )?;
    let size_of_raw_data = align(
        u32::try_from(new.data.len()).map_err(|_| FileParseError::ValueTooLarge)?,
        file_alignment,
    )?;
    let header_end = section_header_offset
        .checked_add(40)
        .ok_or(FileParseError::BufferOverflow)?;
    let old_headers = pe.optional_header.size_of_headers.value;
    let header_growth = if header_end > old_headers as usize {
        align(
            old_headers
                .checked_add(40)
                .ok_or(FileParseError::ValueTooLarge)?,
            file_alignment,
        )?
        .checked_sub(old_headers)
        .ok_or(FileParseError::ValueTooLarge)?
    } else {
        0
    };
    let raw_data_offset = align(raw_end, file_alignment)?
        .checked_add(header_growth)
        .ok_or(FileParseError::ValueTooLarge)?;
    raw_data_offset
        .checked_add(size_of_raw_data)
        .ok_or(FileParseError::ValueTooLarge)?;
    let shifted_len = pe
        .buffer
        .len()
        .checked_add(header_growth as usize)
        .ok_or(FileParseError::ValueTooLarge)?;
    let new_buffer_len = shifted_len
        .max(raw_data_offset as usize)
        .checked_add(size_of_raw_data as usize)
        .ok_or(FileParseError::ValueTooLarge)?;

    Ok(PeInsertSectionPlan {
        section_header_offset,
        virtual_address,
        raw_data_offset,
        size_of_raw_data,
        new_buffer_len,
    })
}

/// When `true`, a planned structural edit should only be simulated (caller checks this flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WriteMode {
    /// Apply mutations to the in-memory buffer (default for `insert_*` APIs).
    #[default]
    Live,
    /// Caller inspects a a format-specific layout plan and skips mutation.
    DryRun,
}

impl WriteMode {
    /// Returns `true` for [`WriteMode::DryRun`].
    pub fn is_dry_run(self) -> bool {
        matches!(self, WriteMode::DryRun)
    }
}
