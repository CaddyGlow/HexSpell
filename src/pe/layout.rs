//! Layout helpers for PE structural edits (section removal, header growth, sync).

use alloc::vec::Vec;

use crate::errors::FileParseError;
use crate::pe::header;
use crate::pe::section::PeSection;
use crate::pe::PE;

fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    (value + alignment - 1) & !(alignment - 1)
}

/// Updates a `u32` field in `buffer` at `offset`.
fn write_u32(buffer: &mut [u8], offset: usize, value: u32) -> Result<(), FileParseError> {
    let end = offset
        .checked_add(4)
        .ok_or(FileParseError::BufferOverflow)?;
    buffer
        .get_mut(offset..end)
        .ok_or(FileParseError::BufferOverflow)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Updates a `u16` field in `buffer` at `offset`.
fn write_u16(buffer: &mut [u8], offset: usize, value: u16) -> Result<(), FileParseError> {
    let end = offset
        .checked_add(2)
        .ok_or(FileParseError::BufferOverflow)?;
    buffer
        .get_mut(offset..end)
        .ok_or(FileParseError::BufferOverflow)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// File pointers must move with their targets, including pointers in raw debug
/// records and COFF metadata rather than only section raw-data pointers.
pub(super) struct FileOffsetFixups(Vec<(usize, u32)>);

impl FileOffsetFixups {
    pub(super) fn capture(pe: &PE) -> Result<Self, FileParseError> {
        let mut fields = Vec::new();
        fields.push((
            pe.coff_header.pointer_to_symbol_table.offset,
            pe.coff_header.pointer_to_symbol_table.value,
        ));
        for section in &pe.sections {
            for field in [
                &section.pointer_to_raw_data,
                &section.pointer_to_relocations,
                &section.pointer_to_linenumbers,
            ] {
                fields.push((field.offset, field.value));
            }
        }
        if pe.optional_header.has_data_directory(header::SECURITY) {
            let field = &pe.optional_header.data_directories[header::SECURITY].virtual_address;
            fields.push((field.offset, field.value));
        }
        if let Some(debug) = pe.debug_directory()? {
            for entry in debug.entries {
                fields.push((
                    entry.pointer_to_raw_data.offset,
                    entry.pointer_to_raw_data.value,
                ));
            }
        }
        Ok(Self(fields))
    }

    pub(super) fn apply(
        &self,
        buffer: &mut [u8],
        edits: &[(usize, usize, usize)],
    ) -> Result<(), FileParseError> {
        let translate = |mut position: usize| -> Result<Option<usize>, FileParseError> {
            for &(start, removed, inserted) in edits {
                let end = start
                    .checked_add(removed)
                    .ok_or(FileParseError::BufferOverflow)?;
                if position >= end {
                    position = position
                        .checked_sub(removed)
                        .and_then(|p| p.checked_add(inserted))
                        .ok_or(FileParseError::BufferOverflow)?;
                } else if position >= start {
                    return Ok(None);
                }
            }
            Ok(Some(position))
        };
        for &(field_offset, value) in &self.0 {
            if value == 0 {
                continue;
            }
            if let Some(field_offset) = translate(field_offset)? {
                let value = translate(value as usize)?.unwrap_or(0);
                write_u32(
                    buffer,
                    field_offset,
                    u32::try_from(value).map_err(|_| FileParseError::ValueTooLarge)?,
                )?;
            }
        }
        Ok(())
    }
}

impl PE {
    /// Renames section `index` (truncated to 8 bytes on disk).
    pub fn rename_section(&mut self, index: usize, new_name: &str) -> Result<(), FileParseError> {
        let section = self
            .sections
            .get_mut(index)
            .ok_or(FileParseError::BufferOverflow)?;
        section.name.update_str(&mut self.buffer, new_name)?;
        Ok(())
    }

    /// Removes section `index`, adjusting file offsets, RVAs, and header counts.
    pub fn remove_section(&mut self, index: usize) -> Result<(), FileParseError> {
        if index >= self.sections.len() {
            return Err(FileParseError::BufferOverflow);
        }
        if self.sections.len() == 1 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let fixups = FileOffsetFixups::capture(self)?;

        let removed = &self.sections[index];
        let header_off = removed.name.offset;
        let raw_ptr = removed.pointer_to_raw_data.value;
        let raw_size = removed.size_of_raw_data.value;
        let removed_rva = removed.virtual_address.value;
        let section_align = self.optional_header.section_alignment.value;
        let removed_virtual = align_up(removed.virtual_size.value, section_align);
        let removed_rva_end = removed_rva.saturating_add(removed_virtual);

        let raw_start = raw_ptr as usize;
        let raw_len = raw_size as usize;

        if raw_len > 0 && raw_start + raw_len <= self.buffer.len() {
            self.buffer.drain(raw_start..raw_start + raw_len);
            fixups.apply(&mut self.buffer, &[(raw_start, raw_len, 0)])?;
            for section in self.sections.iter_mut() {
                if section.pointer_to_raw_data.value > raw_ptr {
                    let new_ptr = section.pointer_to_raw_data.value - raw_size;
                    write_u32(
                        &mut self.buffer,
                        section.pointer_to_raw_data.offset,
                        new_ptr,
                    )?;
                    section.pointer_to_raw_data.value = new_ptr;
                }
            }
        }

        // Compact only the section table. Removing bytes from the whole file
        // would shift every raw payload by 40 and break file alignment.
        let table_end = self
            .sections
            .last()
            .map(|section| section.name.offset + 40)
            .ok_or(FileParseError::InvalidFileFormat)?;
        self.buffer
            .copy_within(header_off + 40..table_end, header_off);
        self.buffer[table_end - 40..table_end].fill(0);

        for (i, section) in self.sections.iter_mut().enumerate() {
            if i == index {
                continue;
            }
            if section.name.offset > header_off {
                shift_section_fields(section, -40);
            }
            if section.virtual_address.value > removed_rva {
                let new_rva = section.virtual_address.value - removed_virtual;
                write_u32(&mut self.buffer, section.virtual_address.offset, new_rva)?;
                section.virtual_address.value = new_rva;
            }
        }

        let active = self.optional_header.active_data_directory_count();
        for dir_index in 0..active {
            let entry = &self.optional_header.data_directories[dir_index];
            if dir_index == header::SECURITY {
                continue;
            }
            let rva = entry.virtual_address.value;
            if rva == 0 {
                continue;
            }
            if rva >= removed_rva && rva < removed_rva_end {
                write_u32(&mut self.buffer, entry.virtual_address.offset, 0)?;
                write_u32(&mut self.buffer, entry.size.offset, 0)?;
            } else if rva >= removed_rva_end {
                let new_rva = rva - removed_virtual;
                write_u32(&mut self.buffer, entry.virtual_address.offset, new_rva)?;
            }
        }

        let new_count = self.coff_header.number_of_sections.value - 1;
        write_u16(
            &mut self.buffer,
            self.coff_header.number_of_sections.offset,
            new_count,
        )?;

        let size_of_image = compute_size_of_image(
            &self.sections,
            index,
            self.optional_header.section_alignment.value,
        );
        write_u32(
            &mut self.buffer,
            self.optional_header.size_of_image.offset,
            size_of_image,
        )?;

        self.sections.remove(index);
        self.coff_header.number_of_sections.value = new_count;
        self.optional_header.size_of_image.value = size_of_image;

        let buffer = core::mem::take(&mut self.buffer);
        *self = PE::from_buffer(buffer)?;
        let checksum = self.calc_checksum();
        self.optional_header
            .checksum
            .update(&mut self.buffer, checksum)?;

        Ok(())
    }

    /// Grows the optional header by `extra_bytes`, shifting the section table and raw data.
    pub fn grow_optional_header(&mut self, extra_bytes: u16) -> Result<(), FileParseError> {
        if extra_bytes == 0 {
            return Ok(());
        }
        let fixups = FileOffsetFixups::capture(self)?;
        let mut edits = Vec::new();

        let optional_start = self.optional_header.magic.offset;
        let old_optional_size = self.coff_header.size_of_optional_header.value as usize;
        let insert_at = optional_start + old_optional_size;
        let extra = extra_bytes as usize;
        let file_align = self.optional_header.file_alignment.value;
        let raw_shift = align_up(extra_bytes as u32, file_align);
        let first_raw = self
            .sections
            .iter()
            .filter(|section| section.size_of_raw_data.value > 0)
            .map(|section| section.pointer_to_raw_data.value as usize)
            .min();

        self.buffer
            .splice(insert_at..insert_at, core::iter::repeat_n(0u8, extra));
        edits.push((insert_at, 0, extra));
        if let Some(first_raw) = first_raw {
            let padding = raw_shift as usize - extra;
            self.buffer.splice(
                first_raw + extra..first_raw + extra,
                core::iter::repeat_n(0u8, padding),
            );
            edits.push((first_raw + extra, 0, padding));
        }

        for section in self.sections.iter_mut() {
            shift_section_fields(section, extra as i32);
            if section.pointer_to_raw_data.value as usize >= insert_at {
                let new_ptr = section.pointer_to_raw_data.value + raw_shift;
                write_u32(
                    &mut self.buffer,
                    section.pointer_to_raw_data.offset,
                    new_ptr,
                )?;
                section.pointer_to_raw_data.value = new_ptr;
            }
        }

        let new_optional_size = old_optional_size + extra;
        if new_optional_size > u16::MAX as usize {
            return Err(FileParseError::ValueTooLarge);
        }
        write_u16(
            &mut self.buffer,
            self.coff_header.size_of_optional_header.offset,
            new_optional_size as u16,
        )?;
        self.coff_header.size_of_optional_header.value = new_optional_size as u16;

        let file_align = self.optional_header.file_alignment.value;
        let section_table_end = self
            .sections
            .last()
            .map(|section| section.characteristics.offset + 4)
            .unwrap_or(insert_at);
        let new_size_of_headers = align_up(section_table_end as u32, file_align);
        write_u32(
            &mut self.buffer,
            self.optional_header.size_of_headers.offset,
            new_size_of_headers,
        )?;
        self.optional_header.size_of_headers.value = new_size_of_headers;

        fixups.apply(&mut self.buffer, &edits)?;

        let buffer = core::mem::take(&mut self.buffer);
        *self = PE::from_buffer(buffer)?;
        let checksum = self.calc_checksum();
        self.optional_header
            .checksum
            .update(&mut self.buffer, checksum)?;
        Ok(())
    }

    /// Recomputes `SizeOfImage`, `SizeOfHeaders`, and the header checksum from the current layout.
    pub fn sync_layout(&mut self) -> Result<(), FileParseError> {
        let section_align = self.optional_header.section_alignment.value;
        let file_align = self.optional_header.file_alignment.value;

        let size_of_image = if let Some(last) = self.sections.last() {
            align_up(
                last.virtual_address.value + last.virtual_size.value,
                section_align,
            )
        } else {
            0
        };
        self.optional_header
            .size_of_image
            .update(&mut self.buffer, size_of_image)?;

        let section_table_end = self
            .sections
            .last()
            .map(|section| section.characteristics.offset + section.characteristics.size)
            .unwrap_or(self.optional_header.magic.offset);
        let size_of_headers = align_up(section_table_end as u32, file_align);
        self.optional_header
            .size_of_headers
            .update(&mut self.buffer, size_of_headers)?;

        let checksum = self.calc_checksum();
        self.optional_header
            .checksum
            .update(&mut self.buffer, checksum)?;
        Ok(())
    }
}

fn shift_section_fields(section: &mut PeSection, delta: i32) {
    let shift = |offset: &mut usize| {
        if delta >= 0 {
            *offset += delta as usize;
        } else {
            *offset -= (-delta) as usize;
        }
    };
    shift(&mut section.name.offset);
    shift(&mut section.virtual_size.offset);
    shift(&mut section.virtual_address.offset);
    shift(&mut section.size_of_raw_data.offset);
    shift(&mut section.pointer_to_raw_data.offset);
    shift(&mut section.pointer_to_relocations.offset);
    shift(&mut section.pointer_to_linenumbers.offset);
    shift(&mut section.number_of_relocations.offset);
    shift(&mut section.number_of_linenumbers.offset);
    shift(&mut section.characteristics.offset);
}

fn compute_size_of_image(sections: &[PeSection], removed_index: usize, section_align: u32) -> u32 {
    sections
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != removed_index)
        .map(|(_, section)| {
            align_up(
                section.virtual_address.value + section.virtual_size.value,
                section_align,
            )
        })
        .max()
        .unwrap_or(0)
}
