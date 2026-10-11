//! Linux module-style appended PKCS#7/CMS signature containers.
//!
//! Layout: unchanged signed bytes, opaque signature, twelve-byte information
//! block, then [`MODULE_SIGNATURE_MARKER`]. The length in the information block
//! is big endian regardless of ELF byte order. Parsing does not verify a signature.
use crate::{
    errors::{FileParseError, Result},
    field::{ByteOrder, Field, FixedBytes},
};
use core::ops::Range;

/// Linux end-of-file marker. Its presence alone does not establish validity.
pub const MODULE_SIGNATURE_MARKER: &[u8; 28] = b"~Module signature appended~\n";
/// Modern Linux module signature type: a PKCS#7/CMS message.
pub const MODULE_SIGNATURE_TYPE_PKCS7: u8 = 2;

/// A bounded modern Linux appended-signature container, with real on-disk fields.
#[derive(Debug)]
pub struct AppendedSignature {
    /// `algo`; zero for the PKCS#7 profile (algorithm is inside CMS).
    pub algo: Field<u8>,
    /// `hash`; zero for the PKCS#7 profile (digest is inside CMS).
    pub hash: Field<u8>,
    /// `id_type`; [`MODULE_SIGNATURE_TYPE_PKCS7`].
    pub id_type: Field<u8>,
    /// `signer_len`; zero for the PKCS#7 profile.
    pub signer_len: Field<u8>,
    /// `key_id_len`; zero for the PKCS#7 profile.
    pub key_id_len: Field<u8>,
    /// Three reserved zero bytes.
    pub padding: Field<FixedBytes<3>>,
    /// `sig_len`; always read/write with [`ByteOrder::Big`].
    pub sig_len: Field<u32>,
    /// Prefix covered by the external signature, including any earlier overlays.
    pub signed_range: Range<usize>,
    /// Opaque PKCS#7/CMS payload, excluding the information block and marker.
    pub signature_range: Range<usize>,
}
impl AppendedSignature {
    /// Size of the Linux `module_signature` information block.
    pub const INFO_SIZE: usize = 12;
    /// Parses the outermost EOF trailer without copying payload bytes.
    ///
    /// Returns `None` when the exact marker is absent at EOF. A present marker
    /// with truncated, overflowing, empty or malformed metadata returns an error.
    /// Only the modern PKCS#7 profile is accepted; legacy signature types are
    /// unsupported. Payload bytes remain opaque, without ASN.1 or trust validation.
    pub fn parse(buffer: &[u8]) -> Result<Option<Self>> {
        if !buffer.ends_with(MODULE_SIGNATURE_MARKER) {
            return Ok(None);
        }
        let info = buffer
            .len()
            .checked_sub(MODULE_SIGNATURE_MARKER.len() + Self::INFO_SIZE)
            .ok_or(FileParseError::BufferOverflow)?;
        let metadata = &buffer[info..info + Self::INFO_SIZE];
        if metadata[2] != MODULE_SIGNATURE_TYPE_PKCS7 {
            return Err(FileParseError::UnsupportedFeature(
                "appended signature is not Linux PKCS#7".into(),
            ));
        }
        if [0, 1, 3, 4, 5, 6, 7].iter().any(|&i| metadata[i] != 0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let sig_len = ByteOrder::Big.read_u32(buffer, info + 8)?;
        let length = usize::try_from(sig_len).map_err(|_| FileParseError::BufferOverflow)?;
        let start = info
            .checked_sub(length)
            .ok_or(FileParseError::BufferOverflow)?;
        if length == 0 || start == 0 {
            return Err(FileParseError::InvalidFileFormat);
        }
        Ok(Some(Self {
            algo: Field::new(metadata[0], info, 1),
            hash: Field::new(metadata[1], info + 1, 1),
            id_type: Field::new(metadata[2], info + 2, 1),
            signer_len: Field::new(metadata[3], info + 3, 1),
            key_id_len: Field::new(metadata[4], info + 4, 1),
            padding: Field::new(
                FixedBytes([metadata[5], metadata[6], metadata[7]]),
                info + 5,
                3,
            ),
            sig_len: Field::new(sig_len, info + 8, 4),
            signed_range: 0..start,
            signature_range: start..info,
        }))
    }
    /// Returns bounded opaque signature bytes from the explicit file buffer.
    pub fn data<'a>(&self, buffer: &'a [u8]) -> Result<&'a [u8]> {
        buffer
            .get(self.signature_range.clone())
            .ok_or(FileParseError::BufferOverflow)
    }
    /// Returns the exact prefix an external verifier must authenticate.
    pub fn signed_data<'a>(&self, buffer: &'a [u8]) -> Result<&'a [u8]> {
        buffer
            .get(self.signed_range.clone())
            .ok_or(FileParseError::BufferOverflow)
    }
}
impl<B: core::ops::Deref<Target = [u8]>> super::ELF<B> {
    /// Reads the outermost Linux module-style appended signature lazily.
    /// No ELF payload or cryptographic verification is performed by this accessor.
    pub fn appended_signature(&self) -> Result<Option<AppendedSignature>> {
        AppendedSignature::parse(&self.buffer)
    }
}

#[cfg(feature = "write")]
mod edit {
    use super::*;
    use crate::elf::{
        header::ElfClass,
        section::{SHT_NOBITS, SHT_NULL},
        ELF,
    };

    /// Byte ranges changed by a transactional appended-signature operation.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AppendedSignatureEditReport {
        /// Exact signed prefix preserved byte-for-byte by the operation.
        pub signed_range: Range<usize>,
        /// Previous outermost container, including its metadata and marker.
        pub previous_range: Option<Range<usize>>,
        /// New outermost container; absent after removal.
        pub range: Option<Range<usize>>,
    }
    // The signature must be outside every ELF-owned extent, including padded
    // header-table entries and the extended-count values stored in section zero.
    fn validate_prefix(image: &ELF) -> Result<()> {
        let limit = image.buffer.len() as u64;
        let check = |offset: u64, size: u64| -> Result<()> {
            if size != 0 && offset.checked_add(size).is_none_or(|end| end > limit) {
                return Err(FileParseError::InvalidFileFormat);
            }
            Ok(())
        };
        let minimum = match image.header.class()? {
            ElfClass::Elf32 => 52,
            ElfClass::Elf64 => 64,
        };
        if image.header.eh_size.value < minimum {
            return Err(FileParseError::InvalidFileFormat);
        }
        check(0, u64::from(image.header.eh_size.value))?;
        check(
            image.header.ph_off.value,
            (image.program_headers.len() as u64)
                .checked_mul(u64::from(image.header.ph_ent_size.value))
                .ok_or(FileParseError::ValueTooLarge)?,
        )?;
        check(
            image.header.sh_off.value,
            (image.section_headers.len() as u64)
                .checked_mul(u64::from(image.header.sh_ent_size.value))
                .ok_or(FileParseError::ValueTooLarge)?,
        )?;
        for program in &image.program_headers {
            check(program.p_offset(), program.p_filesz())?;
        }
        for section in &image.section_headers {
            if !matches!(section.sh_type(), SHT_NOBITS | SHT_NULL) {
                check(section.sh_offset(), section.sh_size())?;
            }
        }
        Ok(())
    }
    impl ELF {
        /// Installs/replaces one outermost Linux PKCS#7 trailer transactionally.
        ///
        /// The nonempty opaque payload must have been signed over the exact original
        /// prefix (excluding the existing outermost trailer, if any). No padding or ELF
        /// field changes are introduced. Existing overlays in that prefix are retained.
        /// Rejects malformed trailers and any ELF range extending into the trailer.
        /// Does not create or verify CMS signatures or imply kernel trust/appraisal.
        pub fn set_appended_signature(
            &mut self,
            signature: &[u8],
        ) -> Result<AppendedSignatureEditReport> {
            if signature.is_empty() {
                return Err(FileParseError::InvalidFileFormat);
            }
            let length =
                u32::try_from(signature.len()).map_err(|_| FileParseError::ValueTooLarge)?;
            let previous = AppendedSignature::parse(&self.buffer)?;
            let prefix_end = previous
                .as_ref()
                .map_or(self.buffer.len(), |s| s.signed_range.end);
            let previous_range = previous.map(|_| prefix_end..self.buffer.len());
            let mut candidate = ELF::from_buffer(self.buffer[..prefix_end].to_vec())?;
            validate_prefix(&candidate)?;
            let end = prefix_end
                .checked_add(signature.len())
                .and_then(|n| {
                    n.checked_add(AppendedSignature::INFO_SIZE + MODULE_SIGNATURE_MARKER.len())
                })
                .ok_or(FileParseError::ValueTooLarge)?;
            candidate.buffer.reserve(end - prefix_end);
            candidate.buffer.extend_from_slice(signature);
            candidate
                .buffer
                .extend_from_slice(&[0, 0, MODULE_SIGNATURE_TYPE_PKCS7, 0, 0, 0, 0, 0]);
            candidate.buffer.extend_from_slice(&length.to_be_bytes());
            candidate.buffer.extend_from_slice(MODULE_SIGNATURE_MARKER);
            let candidate = ELF::from_buffer(candidate.buffer)?;
            candidate.appended_signature()?;
            *self = candidate;
            Ok(AppendedSignatureEditReport {
                signed_range: 0..prefix_end,
                previous_range,
                range: Some(prefix_end..end),
            })
        }
        /// Removes only the outermost valid Linux trailer, leaving its signed prefix intact.
        /// An unsigned image is unchanged. Malformed or ELF-aliased trailers reject without
        /// mutation. Stacked older trailers remain part of the returned signed prefix.
        pub fn remove_appended_signature(&mut self) -> Result<AppendedSignatureEditReport> {
            let Some(signature) = AppendedSignature::parse(&self.buffer)? else {
                return Ok(AppendedSignatureEditReport {
                    signed_range: 0..self.buffer.len(),
                    previous_range: None,
                    range: None,
                });
            };
            let prefix_end = signature.signed_range.end;
            let candidate = ELF::from_buffer(self.buffer[..prefix_end].to_vec())?;
            validate_prefix(&candidate)?;
            let report = AppendedSignatureEditReport {
                signed_range: 0..prefix_end,
                previous_range: Some(prefix_end..self.buffer.len()),
                range: None,
            };
            *self = candidate;
            Ok(report)
        }
    }
}
#[cfg(feature = "write")]
pub use edit::AppendedSignatureEditReport;
