//! Checked structural ELF32/ELF64 serialization in either byte order.
//!
//! This low-level API serializes an explicitly supplied layout. It does not
//! establish an executable ABI profile, synthesize linkage, or relocate payloads.
//! Native Linux AMD64 generation uses [`super::ElfBuilder`] instead.
use super::*;
use crate::{elf::header::ElfClass, field::ByteOrder};

/// Structural ELF header values, independent of the native executable profile.
#[derive(Clone, Copy, Debug)]
pub struct HeaderSpec {
    /// ELF word size (`EI_CLASS`).
    pub class: ElfClass,
    /// Integer byte order (`EI_DATA`).
    pub byte_order: ByteOrder,
    /// ELF OS ABI byte.
    pub os_abi: u8,
    /// `e_type`; object linking is outside this serializer's guarantees.
    pub image_type: u16,
    /// Architecture identifier (`e_machine`).
    pub machine: u16,
    /// Preferred entry address (`e_entry`).
    pub entry: u64,
    /// Architecture-specific header flags or program permissions (`PF_*`).
    pub flags: u32,
    /// Section index of the section-name string table; zero means absent.
    pub section_names: usize,
}
/// Explicit program-header values, using full-width integers before checked encoding.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProgramSpec {
    /// On-disk program or section type.
    pub kind: u32,
    /// Architecture-specific header flags or program permissions (`PF_*`).
    pub flags: u32,
    /// Payload file offset; header tables are appended without moving it.
    pub offset: u64,
    /// Preferred virtual address (`p_vaddr`).
    pub virtual_address: u64,
    /// Physical address (`p_paddr`), usually equal to the virtual address.
    pub physical_address: u64,
    /// Initialized file extent (`p_filesz`).
    pub file_size: u64,
    /// Virtual extent including zero-fill (`p_memsz`).
    pub memory_size: u64,
    /// Required alignment; zero or one means no alignment constraint.
    pub alignment: u64,
}
/// Explicit section-header values. Section zero is supplied automatically.
#[derive(Clone, Copy, Debug, Default)]
pub struct SectionHeaderSpec {
    /// Name offset in the section-name string table.
    pub name: u32,
    /// On-disk program or section type.
    pub kind: u32,
    /// Section attributes (`SHF_*`).
    pub flags: u64,
    /// Section virtual address (`sh_addr`).
    pub address: u64,
    /// Payload file offset; header tables are appended without moving it.
    pub offset: u64,
    /// Section extent (`sh_size`); `SHT_NOBITS` needs no file backing.
    pub size: u64,
    /// Linked section index (`sh_link`).
    pub link: u32,
    /// Type-specific section information (`sh_info`).
    pub info: u32,
    /// Required alignment; zero or one means no alignment constraint.
    pub alignment: u64,
    /// Fixed entry size for tables, zero for other sections.
    pub entry_size: u64,
}
fn encode(out: &mut Vec<u8>, value: u64, width: usize, order: ByteOrder) -> Result<()> {
    if width < 8 && value >= (1u64 << (width * 8)) {
        return Err(FileParseError::ValueTooLarge);
    }
    match order {
        ByteOrder::Little => out.extend_from_slice(&value.to_le_bytes()[..width]),
        ByteOrder::Big => out.extend_from_slice(&value.to_be_bytes()[8 - width..]),
    }
    Ok(())
}
fn checked_extent(offset: u64, size: u64, payload: &[u8]) -> Result<()> {
    if offset
        .checked_add(size)
        .is_none_or(|end| end > payload.len() as u64)
    {
        return Err(FileParseError::BufferOverflow);
    }
    Ok(())
}
/// Emits header tables after a caller-positioned payload and reparses the result.
///
/// `payload` includes reserved ELF header bytes (52 for ELF32, 64 for ELF64),
/// which this function replaces. Payload section/program offsets remain unchanged.
/// Program/section tables are appended with class alignment. Empty `sections`
/// omits the section table unless extended program counts require section zero.
/// `sections[0]` describes ELF section index 1. Extended program counts, section
/// counts and string-table indices use the ABI's section-zero escape encodings.
/// All class-width conversions and referenced payload ranges are checked before
/// returning an image. Input slices are never mutated on failure.
pub fn serialize_layout(
    header: HeaderSpec,
    payload: &[u8],
    programs: &[ProgramSpec],
    sections: &[SectionHeaderSpec],
) -> Result<ELF> {
    let wide = header.class == ElfClass::Elf64;
    let word = if wide { 8 } else { 4 };
    let eh_size = if wide { 64 } else { 52 };
    let ph_size = if wide { 56 } else { 32 };
    let sh_size = if wide { 64 } else { 40 };
    if payload.len() < eh_size {
        return Err(FileParseError::BufferOverflow);
    }
    let needs_sections = !sections.is_empty() || programs.len() >= 0xffff;
    let section_count = if needs_sections {
        sections
            .len()
            .checked_add(1)
            .ok_or(FileParseError::ValueTooLarge)?
    } else {
        0
    };
    if header.section_names >= section_count && header.section_names != 0 {
        return Err(FileParseError::InvalidFileFormat);
    }
    if header.section_names != 0 && sections[header.section_names - 1].kind != 3 {
        return Err(FileParseError::InvalidFileFormat);
    }
    for program in programs {
        checked_extent(program.offset, program.file_size, payload)?;
        if program.file_size > program.memory_size
            || (program.alignment > 1
                && (!program.alignment.is_power_of_two()
                    || program.offset % program.alignment
                        != program.virtual_address % program.alignment))
        {
            return Err(FileParseError::InvalidFileFormat);
        }
    }
    for section in sections {
        if section.alignment > 1 && !section.alignment.is_power_of_two() {
            return Err(FileParseError::InvalidFileFormat);
        }
        if section.kind != 8 {
            checked_extent(section.offset, section.size, payload)?;
        }
        if section.link != 0 && section.link as usize >= section_count {
            return Err(FileParseError::InvalidFileFormat);
        }
    }
    let mut out = payload.to_vec();
    while !out.len().is_multiple_of(word) {
        out.push(0);
    }
    let ph_offset = if programs.is_empty() {
        0
    } else {
        out.len() as u64
    };
    for program in programs {
        let values = if wide {
            vec![
                (u64::from(program.kind), 4),
                (u64::from(program.flags), 4),
                (program.offset, 8),
                (program.virtual_address, 8),
                (program.physical_address, 8),
                (program.file_size, 8),
                (program.memory_size, 8),
                (program.alignment, 8),
            ]
        } else {
            vec![
                (u64::from(program.kind), 4),
                (program.offset, 4),
                (program.virtual_address, 4),
                (program.physical_address, 4),
                (program.file_size, 4),
                (program.memory_size, 4),
                (u64::from(program.flags), 4),
                (program.alignment, 4),
            ]
        };
        for (value, width) in values {
            encode(&mut out, value, width, header.byte_order)?;
        }
    }
    let sh_offset = if needs_sections { out.len() as u64 } else { 0 };
    if needs_sections {
        let null = SectionHeaderSpec {
            size: if section_count >= 0xff00 {
                section_count as u64
            } else {
                0
            },
            link: if header.section_names >= 0xff00 {
                u32::try_from(header.section_names).map_err(|_| FileParseError::ValueTooLarge)?
            } else {
                0
            },
            info: if programs.len() >= 0xffff {
                u32::try_from(programs.len()).map_err(|_| FileParseError::ValueTooLarge)?
            } else {
                0
            },
            ..SectionHeaderSpec::default()
        };
        for section in core::iter::once(&null).chain(sections.iter()) {
            for (value, width) in [
                (u64::from(section.name), 4),
                (u64::from(section.kind), 4),
                (section.flags, word),
                (section.address, word),
                (section.offset, word),
                (section.size, word),
                (u64::from(section.link), 4),
                (u64::from(section.info), 4),
                (section.alignment, word),
                (section.entry_size, word),
            ] {
                encode(&mut out, value, width, header.byte_order)?;
            }
        }
    }
    let mut eh = vec![
        0x7f,
        b'E',
        b'L',
        b'F',
        if wide { 2 } else { 1 },
        if header.byte_order == ByteOrder::Little {
            1
        } else {
            2
        },
        1,
        header.os_abi,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    for (value, width) in [
        (u64::from(header.image_type), 2),
        (u64::from(header.machine), 2),
        (1, 4),
        (header.entry, word),
        (ph_offset, word),
        (sh_offset, word),
        (u64::from(header.flags), 4),
        (eh_size as u64, 2),
        (if programs.is_empty() { 0 } else { ph_size }, 2),
        (programs.len().min(0xffff) as u64, 2),
        (if needs_sections { sh_size } else { 0 }, 2),
        (
            if section_count >= 0xff00 {
                0
            } else {
                section_count as u64
            },
            2,
        ),
        (
            if header.section_names >= 0xff00 {
                0xffff
            } else {
                header.section_names as u64
            },
            2,
        ),
    ] {
        encode(&mut eh, value, width, header.byte_order)?;
    }
    out[..eh_size].copy_from_slice(&eh);
    ELF::from_buffer(out)
}
