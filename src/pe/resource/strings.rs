//! Windows RT_STRING blocks, preserving raw UTF-16 units.
use crate::errors::FileParseError;
use alloc::vec::Vec;
/// Sixteen string slots in one RT_STRING resource.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StringTable {
    pub slots: [Vec<u16>; 16],
}
impl StringTable {
    /// Maps a string identifier to resource block ID and slot.
    pub fn location(id: u32) -> Result<(u32, usize), FileParseError> {
        Ok((
            id.checked_div(16)
                .and_then(|n| n.checked_add(1))
                .ok_or(FileParseError::ValueTooLarge)?,
            (id % 16) as usize,
        ))
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, FileParseError> {
        let mut result = Self::default();
        let mut pos = 0;
        for slot in &mut result.slots {
            let len = crate::utils::extract_u16(bytes, pos)? as usize;
            pos += 2;
            let end = pos
                .checked_add(len * 2)
                .ok_or(FileParseError::ValueTooLarge)?;
            *slot = bytes
                .get(pos..end)
                .ok_or(FileParseError::BufferOverflow)?
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            pos = end;
        }
        if pos != bytes.len() {
            return Err(FileParseError::InvalidFileFormat);
        }
        Ok(result)
    }
    pub fn serialize(&self) -> Result<Vec<u8>, FileParseError> {
        let mut result = Vec::new();
        for slot in &self.slots {
            let len = u16::try_from(slot.len()).map_err(|_| FileParseError::ValueTooLarge)?;
            result.extend_from_slice(&len.to_le_bytes());
            for u in slot {
                result.extend_from_slice(&u.to_le_bytes());
            }
        }
        Ok(result)
    }
}
impl super::ResourceDirectoryOwned {
    /// Updates one language-specific string while preserving all neighboring slots.
    pub fn set_string(
        &mut self,
        id: u32,
        language: u32,
        units: Vec<u16>,
    ) -> Result<(), FileParseError> {
        use super::{ResourceData, ResourceDirectoryOwned, ResourceKey, ResourceNode};
        let (block, slot) = StringTable::location(id)?;
        let path = [
            ResourceKey::Id(6),
            ResourceKey::Id(block),
            ResourceKey::Id(language),
        ];
        let mut table = match self.get(&path) {
            Some(ResourceNode::Data(data)) => StringTable::parse(&data.bytes)?,
            None => StringTable::default(),
            _ => return Err(FileParseError::InvalidFileFormat),
        };
        table.slots[slot] = units;
        let bytes = table.serialize()?;
        let mut candidate = self.clone();
        let mut parent = &mut candidate;
        for key in &path[..2] {
            if !parent.entries.iter().any(|(k, _)| k == key) {
                parent.entries.push((
                    key.clone(),
                    ResourceNode::Directory(ResourceDirectoryOwned::default()),
                ));
            }
            parent = match &mut parent
                .entries
                .iter_mut()
                .find(|(k, _)| k == key)
                .ok_or(FileParseError::InvalidFileFormat)?
                .1
            {
                ResourceNode::Directory(d) => d,
                _ => return Err(FileParseError::InvalidFileFormat),
            }
        }
        if let Some((_, node)) = parent.entries.iter_mut().find(|(k, _)| k == &path[2]) {
            let ResourceNode::Data(data) = node else {
                return Err(FileParseError::InvalidFileFormat);
            };
            data.bytes = bytes;
        } else {
            parent.entries.push((
                path[2].clone(),
                ResourceNode::Data(ResourceData {
                    bytes,
                    code_page: 0,
                    reserved: 0,
                }),
            ));
        }
        *self = candidate;
        Ok(())
    }
    /// Reads one string from an exact language block.
    pub fn string(&self, id: u32, language: u32) -> Result<Option<Vec<u16>>, FileParseError> {
        use super::{ResourceKey, ResourceNode};
        let (block, slot) = StringTable::location(id)?;
        match self.get(&[
            ResourceKey::Id(6),
            ResourceKey::Id(block),
            ResourceKey::Id(language),
        ]) {
            None => Ok(None),
            Some(ResourceNode::Data(data)) => {
                Ok(Some(StringTable::parse(&data.bytes)?.slots[slot].clone()))
            }
            _ => Err(FileParseError::InvalidFileFormat),
        }
    }
}
