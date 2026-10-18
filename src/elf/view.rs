//! Borrowed ELF header inspection without eagerly parsing tables or payloads.

use super::header::{ElfClass, ElfHeader};
use super::program::ProgramHeaderEntry;
use super::section::SectionHeaderEntry;
use crate::errors::FileParseError;
use crate::field::ByteOrder;

/// An ELF file header backed by borrowed bytes.
///
/// Parsing allocates nothing and does not validate referenced tables or payloads.
pub struct ElfHeaders<'a> {
    bytes: &'a [u8],
    /// File header with offsets into the borrowed file.
    pub header: ElfHeader,
}

impl<'a> ElfHeaders<'a> {
    /// Parses only the ELF file header, including class and endianness.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FileParseError> {
        Ok(Self {
            bytes,
            header: ElfHeader::parse(bytes)?,
        })
    }

    /// Returns the original borrowed file bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the file byte order.
    pub fn byte_order(&self) -> Result<ByteOrder, FileParseError> {
        ByteOrder::from_ei_data(self.header.ei_data.value)
    }

    fn entry_offset(
        &self,
        offset: u64,
        size: u16,
        index: usize,
        minimum: usize,
    ) -> Result<usize, FileParseError> {
        if offset == 0 || usize::from(size) < minimum {
            return Err(FileParseError::InvalidFileFormat);
        }
        let start = usize::try_from(offset)
            .map_err(|_| FileParseError::BufferOverflow)?
            .checked_add(
                index
                    .checked_mul(usize::from(size))
                    .ok_or(FileParseError::BufferOverflow)?,
            )
            .ok_or(FileParseError::BufferOverflow)?;
        let end = start
            .checked_add(usize::from(size))
            .ok_or(FileParseError::BufferOverflow)?;
        self.bytes
            .get(start..end)
            .ok_or(FileParseError::BufferOverflow)?;
        Ok(start)
    }

    fn section_entry(&self, index: usize) -> Result<SectionHeaderEntry, FileParseError> {
        let class = self.header.class()?;
        let minimum = match class {
            ElfClass::Elf32 => 40,
            ElfClass::Elf64 => 64,
        };
        let offset = self.entry_offset(
            self.header.sh_off.value,
            self.header.sh_ent_size.value,
            index,
            minimum,
        )?;
        SectionHeaderEntry::parse_one(self.bytes, offset, class, self.byte_order()?)
    }

    /// Resolves the section count, reading section zero only for extended numbering.
    pub fn section_count(&self) -> Result<usize, FileParseError> {
        if self.header.sh_num.value != 0 {
            return Ok(usize::from(self.header.sh_num.value));
        }
        if self.header.sh_off.value == 0 {
            return Ok(0);
        }
        let count = usize::try_from(self.section_entry(0)?.sh_size())
            .map_err(|_| FileParseError::BufferOverflow)?;
        if count < 0xff00 {
            return Err(FileParseError::InvalidFileFormat);
        }
        Ok(count)
    }

    /// Resolves the section-name table index, including canonical `SHN_XINDEX`.
    pub fn section_name_table_index(&self) -> Result<usize, FileParseError> {
        if self.header.sh_strndx.value != 0xffff {
            return Ok(usize::from(self.header.sh_strndx.value));
        }
        let index = self.section_entry(0)?.sh_link() as usize;
        if index < 0xff00 {
            return Err(FileParseError::InvalidFileFormat);
        }
        Ok(index)
    }

    /// Parses one section header on demand; without allocating.
    pub fn section(&self, index: usize) -> Result<SectionHeaderEntry, FileParseError> {
        if index >= self.section_count()? {
            return Err(FileParseError::BufferOverflow);
        }
        self.section_entry(index)
    }

    /// Resolves the program count, reading section zero only for extended numbering.
    pub fn program_count(&self) -> Result<usize, FileParseError> {
        if self.header.ph_num.value == 0xffff {
            let count = self.section_entry(0)?.sh_info() as usize;
            if count < 0xffff {
                return Err(FileParseError::InvalidFileFormat);
            }
            return Ok(count);
        }
        Ok(usize::from(self.header.ph_num.value))
    }

    /// Parses one program header on demand; without allocating.
    pub fn program(&self, index: usize) -> Result<ProgramHeaderEntry, FileParseError> {
        if index >= self.program_count()? {
            return Err(FileParseError::BufferOverflow);
        }
        let class = self.header.class()?;
        let minimum = match class {
            ElfClass::Elf32 => 32,
            ElfClass::Elf64 => 56,
        };
        let offset = self.entry_offset(
            self.header.ph_off.value,
            self.header.ph_ent_size.value,
            index,
            minimum,
        )?;
        ProgramHeaderEntry::parse_one(self.bytes, offset, class, self.byte_order()?)
    }
}
