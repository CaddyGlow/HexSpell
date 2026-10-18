//! Generic version-information blocks. Unknown keys and binary values are preserved.
use crate::errors::FileParseError;
use alloc::vec::Vec;
/// Nested VS_VERSIONINFO block. Text values include their terminating UTF-16 NUL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionBlock {
    pub key: Vec<u16>,
    pub value_type: u16,
    pub value: Vec<u8>,
    pub children: Vec<VersionBlock>,
}
fn aligned(pos: usize) -> usize {
    (pos + 3) & !3
}
impl VersionBlock {
    pub fn parse(bytes: &[u8]) -> Result<Self, FileParseError> {
        let (block, len) = Self::parse_inner(bytes, 0)?;
        if len != bytes.len() {
            return Err(FileParseError::InvalidFileFormat);
        }
        Ok(block)
    }
    fn parse_inner(bytes: &[u8], depth: usize) -> Result<(Self, usize), FileParseError> {
        if depth >= 128 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let len = crate::utils::extract_u16(bytes, 0)? as usize;
        if len < 8 || len > bytes.len() {
            return Err(FileParseError::BufferOverflow);
        }
        let bytes = &bytes[..len];
        let value_len = crate::utils::extract_u16(bytes, 2)? as usize;
        let value_type = crate::utils::extract_u16(bytes, 4)?;
        if value_type > 1 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let mut pos = 6;
        let mut key = Vec::new();
        loop {
            let u = crate::utils::extract_u16(bytes, pos)?;
            pos += 2;
            if u == 0 {
                break;
            }
            key.push(u);
        }
        pos = aligned(pos);
        let size = value_len
            .checked_mul(if value_type == 1 { 2 } else { 1 })
            .ok_or(FileParseError::ValueTooLarge)?;
        let value = if size == 0 {
            Vec::new()
        } else {
            bytes
                .get(pos..pos + size)
                .ok_or(FileParseError::BufferOverflow)?
                .to_vec()
        };
        pos += size;
        let mut children = Vec::new();
        while aligned(pos) < len {
            pos = aligned(pos);
            let (child, size) = Self::parse_inner(&bytes[pos..], depth + 1)?;
            children.push(child);
            pos += size;
        }
        Ok((
            Self {
                key,
                value_type,
                value,
                children,
            },
            len,
        ))
    }
    pub fn serialize(&self) -> Result<Vec<u8>, FileParseError> {
        self.emit(0)
    }
    fn emit(&self, depth: usize) -> Result<Vec<u8>, FileParseError> {
        if depth >= 128
            || self.value_type > 1
            || self.key.contains(&0)
            || (self.value_type == 1 && !self.value.len().is_multiple_of(2))
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        let mut bytes = alloc::vec![0;6];
        for unit in &self.key {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        if !self.value.is_empty() {
            bytes.resize(aligned(bytes.len()), 0);
            bytes.extend_from_slice(&self.value);
        }
        for child in &self.children {
            bytes.resize(aligned(bytes.len()), 0);
            bytes.extend_from_slice(&child.emit(depth + 1)?);
        }
        let len = u16::try_from(bytes.len()).map_err(|_| FileParseError::ValueTooLarge)?;
        let value_len = u16::try_from(self.value.len() / if self.value_type == 1 { 2 } else { 1 })
            .map_err(|_| FileParseError::ValueTooLarge)?;
        bytes[..2].copy_from_slice(&len.to_le_bytes());
        bytes[2..4].copy_from_slice(&value_len.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.value_type.to_le_bytes());
        Ok(bytes)
    }
}
