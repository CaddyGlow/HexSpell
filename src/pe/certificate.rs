//! Authenticode certificate table (`IMAGE_DIRECTORY_ENTRY_SECURITY`).

use alloc::vec::Vec;

use crate::errors::FileParseError;
use crate::field::Field;
use crate::utils::{extract_u16, extract_u32};

/// `WIN_CERT_REVISION_2_0`.
pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;
/// `WIN_CERT_TYPE_PKCS_SIGNED_DATA`.
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// `WIN_CERTIFICATE` header (variable-length PKCS#7 blob follows).
pub struct WinCertificate {
    /// Total length of the certificate entry, including this header (`dwLength`).
    pub length: Field<u32>,
    /// Certificate revision (`wRevision`).
    pub revision: Field<u16>,
    /// Certificate type (`wCertificateType`).
    pub certificate_type: Field<u16>,
    /// Absolute file offset of the first certificate data byte.
    pub data_offset: usize,
}

/// Read-only view of the certificate table overlay.
pub struct CertificateTable {
    /// File offset of the first `WIN_CERTIFICATE` (`IMAGE_DIRECTORY_ENTRY_SECURITY` uses a file offset, not an RVA).
    pub offset: usize,
    /// Total size in bytes from the data directory entry.
    pub size: usize,
    /// Parsed certificate headers chained in file order.
    pub certificates: Vec<WinCertificate>,
}

impl WinCertificate {
    /// Minimum header size before certificate data.
    pub const HEADER_SIZE: usize = 8;

    /// Parses one `WIN_CERTIFICATE` at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if offset
            .checked_add(Self::HEADER_SIZE)
            .is_none_or(|end| end > buffer.len())
        {
            return Err(FileParseError::BufferOverflow);
        }

        let length = extract_u32(buffer, offset)?;
        if length < Self::HEADER_SIZE as u32 {
            return Err(FileParseError::InvalidFileFormat);
        }

        Ok(WinCertificate {
            length: Field::new(length, offset, 4),
            revision: Field::new(extract_u16(buffer, offset + 4)?, offset + 4, 2),
            certificate_type: Field::new(extract_u16(buffer, offset + 6)?, offset + 6, 2),
            data_offset: offset + Self::HEADER_SIZE,
        })
    }

    /// Returns the PKCS#7 / certificate payload bytes.
    pub fn data<'a>(&self, buffer: &'a [u8]) -> Result<&'a [u8], FileParseError> {
        let end = self
            .length
            .offset
            .checked_add(self.length.value as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        buffer
            .get(self.data_offset..end)
            .ok_or(FileParseError::BufferOverflow)
    }
}

impl CertificateTable {
    /// Parses the certificate table at `file_offset` with total `size`.
    ///
    /// `file_offset` and `size` come from `IMAGE_DIRECTORY_ENTRY_SECURITY` (file offsets, not RVAs).
    pub fn parse(buffer: &[u8], file_offset: u32, size: u32) -> Result<Self, FileParseError> {
        if file_offset == 0 && size == 0 {
            return Ok(CertificateTable {
                offset: 0,
                size: 0,
                certificates: Vec::new(),
            });
        }

        if file_offset == 0 || size == 0 || !file_offset.is_multiple_of(8) {
            return Err(FileParseError::InvalidFileFormat);
        }

        let offset = file_offset as usize;
        let total = size as usize;
        let end = offset
            .checked_add(total)
            .ok_or(FileParseError::BufferOverflow)?;
        if buffer.len() < end {
            return Err(FileParseError::BufferOverflow);
        }

        let mut certificates = Vec::new();
        let mut cursor = offset;
        while cursor < end {
            // Bound the parser by the directory, not merely the containing file.
            let cert = WinCertificate::parse(&buffer[..end], cursor)?;
            let payload_end = cursor
                .checked_add(cert.length.value as usize)
                .ok_or(FileParseError::BufferOverflow)?;
            let aligned = (cert.length.value as usize)
                .checked_add(7)
                .ok_or(FileParseError::BufferOverflow)?
                & !7;
            let next = cursor
                .checked_add(aligned)
                .ok_or(FileParseError::BufferOverflow)?;
            if payload_end > end || next > end {
                return Err(FileParseError::BufferOverflow);
            }
            certificates.push(cert);
            cursor = next;
        }

        Ok(CertificateTable {
            offset,
            size: total,
            certificates,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn record(length: u32, total: usize) -> Vec<u8> {
        let mut bytes = vec![0; total];
        bytes[8..12].copy_from_slice(&length.to_le_bytes());
        bytes[12..16].copy_from_slice(&[0, 2, 2, 0]);
        bytes
    }

    #[test]
    fn rejects_record_crossing_declared_table() {
        assert!(CertificateTable::parse(&record(16, 24), 8, 8).is_err());
    }

    #[test]
    fn rejects_alignment_crossing_declared_table() {
        assert!(CertificateTable::parse(&record(9, 24), 8, 9).is_err());
    }

    #[test]
    fn rejects_partial_header_and_inconsistent_directory() {
        assert!(CertificateTable::parse(&record(8, 24), 8, 7).is_err());
        assert!(CertificateTable::parse(&record(8, 24), 0, 8).is_err());
        assert!(CertificateTable::parse(&record(8, 24), 8, 0).is_err());
        assert!(WinCertificate::parse(&[], usize::MAX).is_err());
    }

    #[test]
    fn accepts_aligned_records_and_preserves_unknown_types() {
        let mut bytes = record(9, 32);
        bytes[24..28].copy_from_slice(&8_u32.to_le_bytes());
        let table = CertificateTable::parse(&bytes, 8, 24).unwrap();
        assert_eq!(table.certificates.len(), 2);
        assert_eq!(table.certificates[0].data(&bytes).unwrap(), &[0]);
        assert_eq!(table.certificates[1].certificate_type.value, 0);
        assert!(CertificateTable::parse(&[], 0, 0)
            .unwrap()
            .certificates
            .is_empty());
    }
}
