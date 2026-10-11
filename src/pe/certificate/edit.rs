//! Owned certificate records and transactional PE overlay editing.
use super::{CertificateTable, WIN_CERT_REVISION_2_0, WIN_CERT_TYPE_PKCS_SIGNED_DATA};
use crate::{
    errors::{FileParseError, Result},
    pe::{header, PE},
};
use alloc::vec::Vec;
use core::ops::Range;

/// An opaque `WIN_CERTIFICATE` record. No cryptographic validation is performed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateOwned {
    /// Certificate revision, including unknown values.
    pub revision: u16,
    /// Certificate type, including unknown values.
    pub certificate_type: u16,
    /// Payload excluding the eight-byte header and alignment padding.
    pub data: Vec<u8>,
    /// Original alignment bytes. Serialization preserves these when their length fits.
    pub padding: Vec<u8>,
}
impl CertificateOwned {
    /// Wraps caller-provided PKCS#7 bytes in a revision 2.0 record.
    pub fn pkcs_signed_data(data: Vec<u8>) -> Self {
        Self {
            revision: WIN_CERT_REVISION_2_0,
            certificate_type: WIN_CERT_TYPE_PKCS_SIGNED_DATA,
            data,
            padding: Vec::new(),
        }
    }
}
/// Lossless owned records in file order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertificateTableOwned {
    /// Records to serialize, including unknown revisions/types.
    pub certificates: Vec<CertificateOwned>,
}
impl CertificateTableOwned {
    /// Copies bounded records and their alignment padding from an existing table.
    pub fn from_table(table: &CertificateTable, buffer: &[u8]) -> Result<Self> {
        // Public Field values may have been changed independently of the buffer.
        let parsed = CertificateTable::parse(
            buffer,
            u32::try_from(table.offset).map_err(|_| FileParseError::ValueTooLarge)?,
            u32::try_from(table.size).map_err(|_| FileParseError::ValueTooLarge)?,
        )?;
        let mut certificates = Vec::new();
        for cert in parsed.certificates {
            let data = cert.data(buffer)?.to_vec();
            let end = cert.data_offset + data.len();
            let padded = end.checked_add(7).ok_or(FileParseError::ValueTooLarge)? & !7;
            certificates.push(CertificateOwned {
                revision: cert.revision.value,
                certificate_type: cert.certificate_type.value,
                data,
                padding: buffer[end..padded].to_vec(),
            });
        }
        Ok(Self { certificates })
    }
    /// Serializes eight-byte-aligned records; new or resized padding is zero-filled.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut total = 0usize;
        for cert in &self.certificates {
            let length = cert
                .data
                .len()
                .checked_add(8)
                .ok_or(FileParseError::ValueTooLarge)?;
            u32::try_from(length).map_err(|_| FileParseError::ValueTooLarge)?;
            total = total
                .checked_add(length.checked_add(7).ok_or(FileParseError::ValueTooLarge)? & !7)
                .ok_or(FileParseError::ValueTooLarge)?;
        }
        u32::try_from(total).map_err(|_| FileParseError::ValueTooLarge)?;
        let mut bytes = Vec::with_capacity(total);
        for cert in &self.certificates {
            let length = cert.data.len() + 8;
            bytes.extend_from_slice(&(length as u32).to_le_bytes());
            bytes.extend_from_slice(&cert.revision.to_le_bytes());
            bytes.extend_from_slice(&cert.certificate_type.to_le_bytes());
            bytes.extend_from_slice(&cert.data);
            let padding = (8 - length % 8) % 8;
            if cert.padding.len() == padding {
                bytes.extend_from_slice(&cert.padding);
            } else {
                bytes.resize(bytes.len() + padding, 0);
            }
        }
        Ok(bytes)
    }
}
/// File locations before and after a certificate-table operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateEditReport {
    /// Previous certificate table, excluding any preceding overlay bytes.
    pub previous_range: Option<Range<usize>>,
    /// New certificate table; absent after removal.
    pub range: Option<Range<usize>>,
}
fn invalid() -> FileParseError {
    FileParseError::InvalidFileFormat
}
fn checked_range(start: usize, size: usize, limit: usize) -> Result<Range<usize>> {
    let end = start
        .checked_add(size)
        .ok_or(FileParseError::BufferOverflow)?;
    if end > limit {
        return Err(FileParseError::BufferOverflow);
    }
    Ok(start..end)
}
fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}
// Require an EOF overlay without aliases into headers, sections, or auxiliary data.
fn preflight(pe: &PE) -> Result<Option<Range<usize>>> {
    let h = &pe.optional_header;
    let base = if h.magic.value == 0x20b { 112 } else { 96 };
    if !h.has_data_directory(header::SECURITY)
        || usize::from(pe.coff_header.size_of_optional_header.value)
            < base + (header::SECURITY + 1) * 8
    {
        return Err(FileParseError::UnsupportedFeature(
            "PE certificate editing requires a security directory slot".into(),
        ));
    }
    let slot = &h.data_directories[header::SECURITY];
    let table = CertificateTable::parse(&pe.buffer, slot.virtual_address.value, slot.size.value)?;
    let target = if table.size == 0 {
        None
    } else {
        let target = checked_range(table.offset, table.size, pe.buffer.len())?;
        if target.end != pe.buffer.len() {
            return Err(FileParseError::UnsupportedFeature(
                "PE certificate editing requires an EOF table".into(),
            ));
        }
        Some(target)
    };
    let header_end = h.size_of_headers.value as usize;
    let section_end = h
        .magic
        .offset
        .checked_add(usize::from(pe.coff_header.size_of_optional_header.value))
        .and_then(|n| n.checked_add(pe.sections.len().checked_mul(40)?))
        .ok_or(FileParseError::ValueTooLarge)?;
    if header_end < section_end || header_end > pe.buffer.len() {
        return Err(invalid());
    }
    let check = |start: usize, size: usize| -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        let referenced = checked_range(start, size, pe.buffer.len())?;
        if target.as_ref().is_some_and(|t| overlaps(t, &referenced)) {
            return Err(invalid());
        }
        Ok(())
    };
    check(0, header_end)?;
    for section in &pe.sections {
        check(
            section.pointer_to_raw_data.value as usize,
            section.size_of_raw_data.value as usize,
        )?;
        check(
            section.pointer_to_relocations.value as usize,
            section.number_of_relocations.value as usize * 10,
        )?;
        check(
            section.pointer_to_linenumbers.value as usize,
            section.number_of_linenumbers.value as usize * 6,
        )?;
    }
    let symbols = &pe.coff_header;
    if symbols.pointer_to_symbol_table.value != 0 {
        let start = symbols.pointer_to_symbol_table.value as usize;
        let size = (symbols.number_of_symbols.value as usize)
            .checked_mul(18)
            .ok_or(FileParseError::ValueTooLarge)?;
        let strings = start
            .checked_add(size)
            .ok_or(FileParseError::ValueTooLarge)?;
        let string_size = crate::utils::extract_u32(&pe.buffer, strings)? as usize;
        if string_size < 4 {
            return Err(invalid());
        }
        check(
            start,
            size.checked_add(string_size)
                .ok_or(FileParseError::ValueTooLarge)?,
        )?;
    } else if symbols.number_of_symbols.value != 0 {
        return Err(invalid());
    }
    if let Some(debug) = pe.debug_directory()? {
        for entry in debug.entries {
            check(
                entry.pointer_to_raw_data.value as usize,
                entry.size_of_data.value as usize,
            )?;
        }
    }
    Ok(target)
}
impl PE {
    /// Copies certificate records and padding; an unsigned image yields an empty table.
    pub fn owned_certificates(&self) -> Result<CertificateTableOwned> {
        match self.certificates()? {
            Some(table) => CertificateTableOwned::from_table(&table, &self.buffer),
            None => Ok(CertificateTableOwned::default()),
        }
    }
    /// Replaces the EOF certificate table transactionally and updates its directory/checksum.
    ///
    /// Preserves bytes preceding the table, including overlays. An empty table removes it.
    /// Rejects missing directory slots, non-EOF tables, malformed records and referenced aliases.
    /// Payloads remain opaque: this does not sign or verify Authenticode content. Finish all
    /// other edits and let the signing library compute the appropriate digest first.
    pub fn replace_certificates(
        &mut self,
        table: &CertificateTableOwned,
    ) -> Result<CertificateEditReport> {
        let serialized = table.serialize()?;
        let mut candidate = PE::from_buffer(self.buffer.clone())?;
        let previous_range = preflight(&candidate)?;
        if let Some(old) = &previous_range {
            candidate.buffer.truncate(old.start);
        }
        let range = if serialized.is_empty() {
            None
        } else {
            let start = candidate
                .buffer
                .len()
                .checked_add(7)
                .ok_or(FileParseError::ValueTooLarge)?
                & !7;
            let end = start
                .checked_add(serialized.len())
                .ok_or(FileParseError::ValueTooLarge)?;
            u32::try_from(end).map_err(|_| FileParseError::ValueTooLarge)?;
            candidate.buffer.resize(start, 0);
            candidate.buffer.extend_from_slice(&serialized);
            Some(start..end)
        };
        let slot = &mut candidate.optional_header.data_directories[header::SECURITY];
        slot.virtual_address.update(
            &mut candidate.buffer,
            range.as_ref().map_or(0, |r| r.start as u32),
        )?;
        slot.size
            .update(&mut candidate.buffer, serialized.len() as u32)?;
        let checksum = candidate.calc_checksum();
        candidate
            .optional_header
            .checksum
            .update(&mut candidate.buffer, checksum)?;
        let candidate = PE::from_buffer(candidate.buffer)?;
        *self = candidate;
        Ok(CertificateEditReport {
            previous_range,
            range,
        })
    }
    /// Appends one opaque record, preserving existing records and their padding.
    pub fn append_certificate(
        &mut self,
        certificate: &CertificateOwned,
    ) -> Result<CertificateEditReport> {
        let mut table = self.owned_certificates()?;
        table.certificates.push(certificate.clone());
        self.replace_certificates(&table)
    }
    /// Removes an isolated EOF table, clears its directory and updates the checksum.
    pub fn remove_certificates(&mut self) -> Result<CertificateEditReport> {
        self.replace_certificates(&CertificateTableOwned::default())
    }
}
