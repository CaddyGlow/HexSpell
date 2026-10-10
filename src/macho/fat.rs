//! FAT (universal) Mach-O wrapper parsing.
//!
//! A FAT binary begins with a `fat_header` followed by one `fat_arch` (or `fat_arch_64`) per
//! embedded thin Mach-O. HexSpell unpacks a chosen slice into a standalone [`crate::macho::MachO`].

use alloc::vec;
use alloc::vec::Vec;

use crate::errors::FileParseError;
use crate::field::ByteOrder;

/// One architecture slice inside a FAT binary (`fat_arch` / `fat_arch_64`).
#[derive(Debug, Clone)]
pub struct FatArch {
    /// CPU type of the slice.
    pub cpu_type: u32,
    /// CPU subtype of the slice.
    pub cpu_subtype: u32,
    /// File offset of the embedded thin Mach-O.
    pub offset: u64,
    /// Size in bytes of the embedded thin Mach-O.
    pub size: u64,
    /// Alignment as a power of two.
    pub align: u32,
}

/// A parsed FAT header plus the list of embedded architecture slices.
#[derive(Debug, Clone)]
pub struct FatHeader {
    /// Byte order the FAT header is stored in (always big-endian in practice).
    pub order: ByteOrder,
    /// `true` for the `fat_arch_64` layout (`0xCAFEBABF`).
    pub is_64: bool,
    /// Architecture slices in file order.
    pub arches: Vec<FatArch>,
}

impl FatArch {
    /// Byte range `(start, end)` of this slice inside a FAT file.
    pub fn byte_range(&self) -> Result<(usize, usize), FileParseError> {
        let start = usize::try_from(self.offset).map_err(|_| FileParseError::BufferOverflow)?;
        let end = start
            .checked_add(usize::try_from(self.size).map_err(|_| FileParseError::BufferOverflow)?)
            .ok_or(FileParseError::BufferOverflow)?;
        Ok((start, end))
    }
}

impl FatHeader {
    /// Detects a FAT magic at the start of `buffer` and, if present, parses the arch table.
    ///
    /// Returns `Ok(None)` when `buffer` is not a FAT binary.
    pub fn parse(buffer: &[u8]) -> Result<Option<Self>, FileParseError> {
        let Some(view) = FatHeaders::parse(buffer)? else {
            return Ok(None);
        };
        let mut arches = Vec::with_capacity(view.count);
        for index in 0..view.count {
            arches.push(view.arch(index)?);
        }
        Ok(Some(Self {
            order: view.order,
            is_64: view.is_64,
            arches,
        }))
    }

    /// Returns a sub-slice of `buffer` for `arch` without copying.
    pub fn slice_ref<'a>(
        &self,
        buffer: &'a [u8],
        arch: &FatArch,
    ) -> Result<&'a [u8], FileParseError> {
        let (start, end) = arch.byte_range()?;
        buffer.get(start..end).ok_or(FileParseError::BufferOverflow)
    }

    /// Copies the thin Mach-O bytes for `arch` out of `buffer`.
    pub fn slice_bytes(&self, buffer: &[u8], arch: &FatArch) -> Result<Vec<u8>, FileParseError> {
        Ok(self.slice_ref(buffer, arch)?.to_vec())
    }

    /// Builds a FAT binary from thin Mach-O slices.
    ///
    /// Each tuple is `(arch metadata, thin Mach-O bytes)`. Offsets are assigned sequentially with
    /// the alignment given by `FatArch::align`.
    pub fn build(slices: &[(FatArch, &[u8])]) -> Result<Vec<u8>, FileParseError> {
        if slices.is_empty() {
            return Err(FileParseError::InvalidFileFormat);
        }
        let is_64 = slices
            .iter()
            .any(|(_, data)| data.len() > u32::MAX as usize);
        let arch_size = if is_64 { 32 } else { 20 };
        let header_size = 8 + arch_size * slices.len();

        let mut arches = Vec::with_capacity(slices.len());
        let mut cursor = header_size;
        for (template, data) in slices {
            let align = 1usize << template.align.min(31);
            cursor = align_up(cursor, align);
            arches.push(FatArch {
                cpu_type: template.cpu_type,
                cpu_subtype: template.cpu_subtype,
                offset: cursor as u64,
                size: data.len() as u64,
                align: template.align,
            });
            cursor += data.len();
        }

        let total_size = cursor;
        let mut out = vec![0u8; total_size];
        let order = ByteOrder::Big;
        let magic = if is_64 { 0xCAFE_BABF } else { 0xCAFE_BABE };
        order.write_u32(&mut out, 0, magic);
        order.write_u32(&mut out, 4, arches.len() as u32);

        for (i, arch) in arches.iter().enumerate() {
            let base = 8 + i * arch_size;
            order.write_u32(&mut out, base, arch.cpu_type);
            order.write_u32(&mut out, base + 4, arch.cpu_subtype);
            if is_64 {
                order.write_u64(&mut out, base + 8, arch.offset);
                order.write_u64(&mut out, base + 16, arch.size);
                order.write_u32(&mut out, base + 24, arch.align);
            } else {
                order.write_u32(&mut out, base + 8, arch.offset as u32);
                order.write_u32(&mut out, base + 12, arch.size as u32);
                order.write_u32(&mut out, base + 16, arch.align);
            }
        }

        for (arch, data) in arches.iter().zip(slices.iter().map(|(_, d)| *d)) {
            let start = arch.offset as usize;
            out[start..start + data.len()].copy_from_slice(data);
        }

        Ok(out)
    }

    /// Merges a new thin slice into an existing FAT binary (or creates a new FAT when `fat` is thin).
    pub fn merge(
        fat_buffer: &[u8],
        new_arch: FatArch,
        new_data: &[u8],
    ) -> Result<Vec<u8>, FileParseError> {
        let mut slices: Vec<(FatArch, Vec<u8>)> = if let Some(existing) = Self::parse(fat_buffer)? {
            existing
                .arches
                .iter()
                .map(|a| Ok((a.clone(), existing.slice_bytes(fat_buffer, a)?)))
                .collect::<Result<Vec<_>, FileParseError>>()?
        } else {
            vec![(
                FatArch {
                    cpu_type: 0,
                    cpu_subtype: 0,
                    offset: 0,
                    size: fat_buffer.len() as u64,
                    align: 0,
                },
                fat_buffer.to_vec(),
            )]
        };

        slices.push((new_arch, new_data.to_vec()));
        let refs: Vec<(FatArch, &[u8])> = slices
            .iter()
            .map(|(a, d)| (a.clone(), d.as_slice()))
            .collect();
        Self::build(&refs)
    }
}

fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

/// Borrowed FAT header and architecture table; parsing allocates nothing.
pub struct FatHeaders<'a> {
    bytes: &'a [u8],
    /// FAT header byte order.
    pub order: ByteOrder,
    /// Whether architecture entries use the 64-bit layout.
    pub is_64: bool,
    /// Number of architecture entries.
    pub count: usize,
}

impl<'a> FatHeaders<'a> {
    /// Detects FAT input and validates the architecture table extent without collecting it.
    pub fn parse(bytes: &'a [u8]) -> Result<Option<Self>, FileParseError> {
        let Some((order, is_64, count)) = layout(bytes)? else {
            return Ok(None);
        };
        let stride: usize = if is_64 { 32 } else { 20 };
        let end = count
            .checked_mul(stride)
            .and_then(|n| n.checked_add(8))
            .ok_or(FileParseError::BufferOverflow)?;
        if count == 0 {
            return Err(FileParseError::BufferOverflow);
        }
        bytes.get(..end).ok_or(FileParseError::BufferOverflow)?;
        Ok(Some(Self {
            bytes,
            order,
            is_64,
            count,
        }))
    }

    /// Reads one architecture entry without allocating.
    pub fn arch(&self, index: usize) -> Result<FatArch, FileParseError> {
        if index >= self.count {
            return Err(FileParseError::BufferOverflow);
        }
        let stride: usize = if self.is_64 { 32 } else { 20 };
        let base = index
            .checked_mul(stride)
            .and_then(|n| n.checked_add(8))
            .ok_or(FileParseError::BufferOverflow)?;
        // Also bounds-check if public count/layout fields have been changed.
        let end = base
            .checked_add(stride)
            .ok_or(FileParseError::BufferOverflow)?;
        self.bytes
            .get(base..end)
            .ok_or(FileParseError::BufferOverflow)?;
        let (offset, size, align) = if self.is_64 {
            (
                self.order.read_u64(self.bytes, base + 8)?,
                self.order.read_u64(self.bytes, base + 16)?,
                self.order.read_u32(self.bytes, base + 24)?,
            )
        } else {
            (
                u64::from(self.order.read_u32(self.bytes, base + 8)?),
                u64::from(self.order.read_u32(self.bytes, base + 12)?),
                self.order.read_u32(self.bytes, base + 16)?,
            )
        };
        Ok(FatArch {
            cpu_type: self.order.read_u32(self.bytes, base)?,
            cpu_subtype: self.order.read_u32(self.bytes, base + 4)?,
            offset,
            size,
            align,
        })
    }

    /// Borrows the thin slice for a selected architecture.
    pub fn slice(&self, index: usize) -> Result<&'a [u8], FileParseError> {
        let (start, end) = self.arch(index)?.byte_range()?;
        self.bytes
            .get(start..end)
            .ok_or(FileParseError::BufferOverflow)
    }
}

pub(crate) fn layout(bytes: &[u8]) -> Result<Option<(ByteOrder, bool, usize)>, FileParseError> {
    let Some(raw) = bytes.get(..4) else {
        return Ok(None);
    };
    let magic: [u8; 4] = raw.try_into().map_err(|_| FileParseError::BufferOverflow)?;
    let (order, is_64) = match u32::from_be_bytes(magic) {
        0xcafebabe => (ByteOrder::Big, false),
        0xcafebabf => (ByteOrder::Big, true),
        _ => match u32::from_le_bytes(magic) {
            0xcafebabe => (ByteOrder::Little, false),
            0xcafebabf => (ByteOrder::Little, true),
            _ => return Ok(None),
        },
    };
    let count = order.read_u32(bytes, 4)? as usize;
    Ok(Some((order, is_64, count)))
}
