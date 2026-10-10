//! Architecture-specific PE metadata (ARM64x, CHPE, hybrid load config).

use crate::errors::FileParseError;
use crate::field::Field;
use crate::pe::coff::CoffFileHeader;
use crate::pe::header::{self, DataDirectoryEntry};
use crate::utils::{extract_u32, extract_u64};

/// `IMAGE_FILE_MACHINE_ARM64`.
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
/// `IMAGE_FILE_MACHINE_ARM64X` (ARM64X hybrid).
pub const IMAGE_FILE_MACHINE_ARM64X: u16 = 0xA64E;
/// `IMAGE_FILE_MACHINE_ARMNT` (CHPE on ARM32).
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01C4;

/// Kind of architecture-specific metadata exposed by a PE image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchitectureDataKind {
    /// `IMAGE_DIRECTORY_ENTRY_ARCHITECTURE` raw blob.
    ArchitectureDirectory,
    /// ARM64X hybrid metadata pointer in the load configuration directory.
    Arm64xHybridMetadata,
    /// CHPE metadata pointer in the load configuration directory.
    ChpeMetadata,
    /// No architecture-specific metadata is present.
    None,
}

/// Raw or lightly interpreted architecture-specific metadata.
pub struct ArchitectureData {
    /// Detected metadata kind.
    pub kind: ArchitectureDataKind,
    /// Absolute file offset of the metadata blob or pointer field.
    pub offset: usize,
    /// On-disk byte length when the metadata is a mapped blob (`kind == ArchitectureDirectory`).
    pub size: usize,
    /// Hybrid CHPE / ARM64X code map RVA when available.
    pub code_map_rva: Option<Field<u32>>,
    /// Hybrid CHPE / ARM64X code map size when available.
    pub code_map_size: Option<Field<u32>>,
}

impl ArchitectureData {
    /// Inspects architecture-specific metadata for `machine` and optional load-config hybrid fields.
    pub fn parse(
        buffer: &[u8],
        coff: &CoffFileHeader,
        architecture_directory: &DataDirectoryEntry,
        hybrid_metadata_pointer: Option<u64>,
        chpe_metadata_pointer: Option<u64>,
        rva_to_offset: impl Fn(u32) -> Result<usize, FileParseError>,
    ) -> Result<Self, FileParseError> {
        let machine = coff.machine.value;

        if machine == IMAGE_FILE_MACHINE_ARM64X {
            if let Some(pointer) = hybrid_metadata_pointer.filter(|&value| value != 0) {
                let offset = rva_to_offset(pointer as u32)?;
                return Ok(ArchitectureData {
                    kind: ArchitectureDataKind::Arm64xHybridMetadata,
                    offset,
                    size: 0,
                    code_map_rva: None,
                    code_map_size: None,
                });
            }
        }

        if machine == IMAGE_FILE_MACHINE_ARMNT || machine == IMAGE_FILE_MACHINE_ARM64 {
            if let Some(pointer) = chpe_metadata_pointer.filter(|&value| value != 0) {
                let offset = rva_to_offset(pointer as u32)?;
                return parse_chpe_metadata(buffer, offset);
            }
        }

        if architecture_directory.virtual_address.value != 0
            && architecture_directory.size.value != 0
        {
            let offset = rva_to_offset(architecture_directory.virtual_address.value)?;
            let size = architecture_directory.size.value as usize;
            let end = offset
                .checked_add(size)
                .ok_or(FileParseError::BufferOverflow)?;
            if buffer.len() < end {
                return Err(FileParseError::BufferOverflow);
            }
            return Ok(ArchitectureData {
                kind: ArchitectureDataKind::ArchitectureDirectory,
                offset,
                size,
                code_map_rva: None,
                code_map_size: None,
            });
        }

        Ok(ArchitectureData {
            kind: ArchitectureDataKind::None,
            offset: 0,
            size: 0,
            code_map_rva: None,
            code_map_size: None,
        })
    }
}

/// Extended hybrid fields from `IMAGE_LOAD_CONFIG_DIRECTORY` when present.
pub struct HybridLoadConfigFields {
    /// `CHPEMetadataPointer` / hybrid metadata VA.
    pub hybrid_metadata_pointer: Option<Field<u64>>,
    /// `CHPECodeAddressRangeOffset` when exposed by the load config size.
    pub chpe_code_address_range_offset: Option<Field<u32>>,
    /// `CHPECodeAddressRangeCount` when exposed by the load config size.
    pub chpe_code_address_range_count: Option<Field<u32>>,
}

impl HybridLoadConfigFields {
    /// Parses hybrid / CHPE pointer fields from a load configuration directory blob.
    ///
    /// Returns `UnsupportedFeature` when the on-disk structure is too small for the requested machine.
    pub fn parse(
        buffer: &[u8],
        offset: usize,
        size: u32,
        machine: u16,
        pe_type: header::PEType,
    ) -> Result<Self, FileParseError> {
        let size = size as usize;
        if offset
            .checked_add(size)
            .is_none_or(|end| end > buffer.len())
        {
            return Err(FileParseError::BufferOverflow);
        }
        let mut fields = HybridLoadConfigFields {
            hybrid_metadata_pointer: None,
            chpe_code_address_range_offset: None,
            chpe_code_address_range_count: None,
        };
        if matches!(
            machine,
            IMAGE_FILE_MACHINE_ARMNT | IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARM64X
        ) {
            // CHPEMetadataPointer follows DynamicValueRelocTable in the SDK
            // load-config layout; its offset and width depend on PE magic.
            let (relative, width) = match pe_type {
                header::PEType::PE32 => (124, 4),
                header::PEType::PE32Plus => (200, 8),
            };
            if size < relative + width {
                return Err(FileParseError::UnsupportedFeature(
                    "CHPE metadata pointer (load config too small)".into(),
                ));
            }
            let pointer_offset = offset + relative;
            let value = match pe_type {
                header::PEType::PE32 => extract_u32(buffer, pointer_offset)? as u64,
                header::PEType::PE32Plus => extract_u64(buffer, pointer_offset)?,
            };
            fields.hybrid_metadata_pointer = Some(Field::new(value, pointer_offset, width));
        }
        Ok(fields)
    }
}

fn parse_chpe_metadata(buffer: &[u8], offset: usize) -> Result<ArchitectureData, FileParseError> {
    // IMAGE_ARM64EC_METADATA / CHPE metadata begins with Version (u32).
    if buffer.len() < offset + 12 {
        return Err(FileParseError::BufferOverflow);
    }

    let version = extract_u32(buffer, offset)?;
    if version == 0 {
        return Err(FileParseError::InvalidFileFormat);
    }

    Ok(ArchitectureData {
        kind: ArchitectureDataKind::ChpeMetadata,
        offset,
        size: 0,
        code_map_rva: Some(Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4)),
        code_map_size: Some(Field::new(extract_u32(buffer, offset + 8)?, offset + 8, 4)),
    })
}
