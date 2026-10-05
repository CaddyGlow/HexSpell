//! Borrowed header inspection without copying the executable or parsing its payloads.

use super::{coff::CoffFileHeader, dos::DosHeader, section::PeSection};
use crate::errors::FileParseError;
use crate::utils::{extract_u16, extract_u32};

/// Locate and validate the NT signature without requiring an optional header.
pub fn nt_offset(bytes: &[u8]) -> Result<usize, FileParseError> {
    let nt = DosHeader::parse(bytes)?.e_lfanew.value as usize;
    let end = nt.checked_add(4).ok_or(FileParseError::BufferOverflow)?;
    if bytes.get(nt..end) != Some(b"PE\0\0") {
        return Err(FileParseError::InvalidFileFormat);
    }
    Ok(nt)
}

/// Parsed COFF header with offsets into a borrowed file. Payload validation is caller policy.
pub struct PeHeaders<'a> {
    bytes: &'a [u8],
    pub nt: usize,
    pub coff: CoffFileHeader,
    pub optional: usize,
    pub sections: usize,
}

impl<'a> PeHeaders<'a> {
    /// Parse DOS, NT signature and COFF headers. Optional fields are read on demand.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FileParseError> {
        let nt = nt_offset(bytes)?;
        let optional = nt.checked_add(24).ok_or(FileParseError::BufferOverflow)?;
        let coff = CoffFileHeader::parse(bytes, nt + 4)?;
        let sections = optional
            .checked_add(coff.size_of_optional_header.value as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        Ok(Self {
            bytes,
            nt,
            coff,
            optional,
            sections,
        })
    }

    /// Read the optional-header magic. Does not impose architecture policy.
    pub fn magic(&self) -> Result<u16, FileParseError> {
        extract_u16(self.bytes, self.optional)
    }

    /// Relative start of the data directory table for PE32 or PE32+.
    pub fn directory_offset(&self) -> Result<usize, FileParseError> {
        match self.magic()? {
            0x10b => Ok(96),
            0x20b => Ok(112),
            _ => Err(FileParseError::InvalidFileFormat),
        }
    }

    /// Read a directory slot. Callers decide whether to honor NumberOfRvaAndSizes.
    /// This supports native consumers which inspect fixed slots even when the count is zero.
    pub fn directory_slot(&self, index: usize) -> Result<(u32, u32), FileParseError> {
        let relative = self
            .directory_offset()?
            .checked_add(index.checked_mul(8).ok_or(FileParseError::BufferOverflow)?)
            .ok_or(FileParseError::BufferOverflow)?;
        if relative
            .checked_add(8)
            .ok_or(FileParseError::BufferOverflow)?
            > self.coff.size_of_optional_header.value as usize
        {
            return Err(FileParseError::BufferOverflow);
        }
        let offset = self
            .optional
            .checked_add(relative)
            .ok_or(FileParseError::BufferOverflow)?;
        Ok((
            extract_u32(self.bytes, offset)?,
            extract_u32(self.bytes, offset + 4)?,
        ))
    }

    /// Parse one section header without interpreting or copying its raw data.
    pub fn section(&self, index: usize) -> Result<PeSection, FileParseError> {
        if index >= self.coff.number_of_sections.value as usize {
            return Err(FileParseError::BufferOverflow);
        }
        let offset = self
            .sections
            .checked_add(
                index
                    .checked_mul(40)
                    .ok_or(FileParseError::BufferOverflow)?,
            )
            .ok_or(FileParseError::BufferOverflow)?;
        PeSection::parse_section(self.bytes, offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> Vec<u8> {
        let mut bytes = vec![0; 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[84..86].copy_from_slice(&224u16.to_le_bytes());
        bytes[88..90].copy_from_slice(&0x10bu16.to_le_bytes());
        bytes
    }

    #[test]
    fn truncated_headers_and_hostile_offsets_do_not_panic() {
        let bytes = image();
        for end in 0..88 {
            assert!(PeHeaders::parse(&bytes[..end]).is_err());
        }
        let mut bytes = bytes;
        bytes[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(PeHeaders::parse(&bytes).is_err());
    }

    #[test]
    fn fixed_directory_slots_can_be_read_without_declared_count() {
        let mut bytes = image();
        bytes[200..204].copy_from_slice(&0x1000u32.to_le_bytes());
        let headers = PeHeaders::parse(&bytes).unwrap();
        assert_eq!(headers.directory_slot(2).unwrap(), (0x1000, 0));
        assert!(headers.directory_slot(usize::MAX).is_err());
        assert!(headers.section(usize::MAX).is_err());
    }
}
