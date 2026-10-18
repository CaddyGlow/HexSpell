use super::{ResourceDirectoryNode, ResourceEntry};
use crate::{errors::FileParseError, pe::PE};
use alloc::vec::Vec;

/// Resource key, preserving raw UTF-16 including unpaired surrogates.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ResourceKey {
    Name(Vec<u16>),
    Id(u32),
}
impl From<&str> for ResourceKey {
    fn from(value: &str) -> Self {
        Self::Name(value.encode_utf16().collect())
    }
}
/// Owned resource bytes and leaf metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResourceData {
    pub bytes: Vec<u8>,
    pub code_page: u32,
    pub reserved: u32,
}
/// Owned directory or leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceNode {
    Directory(ResourceDirectoryOwned),
    Data(ResourceData),
}
/// Lossless editable resource directory. Serialization sorts keys canonically.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResourceDirectoryOwned {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub entries: Vec<(ResourceKey, ResourceNode)>,
}
/// Alias for an owned root directory.
pub type OwnedResources = ResourceDirectoryOwned;
impl ResourceDirectoryOwned {
    /// Imports resources, checking complete payload extents and preserving UTF-16 keys.
    pub fn from_pe(pe: &PE) -> Result<Self, FileParseError> {
        match pe.resources()? {
            Some(tree) => {
                let size = pe.optional_header.data_directories[crate::pe::header::RESOURCE]
                    .size
                    .value as usize;
                let directory = &pe.optional_header.data_directories[crate::pe::header::RESOURCE];
                super::ResourceDataEntry {
                    offset_to_data: directory.virtual_address.clone(),
                    size: directory.size.clone(),
                    code_page: crate::field::Field::new(0, 0, 4),
                    reserved: crate::field::Field::new(0, 0, 4),
                }
                .payload(pe)?;
                let end = tree
                    .offset
                    .checked_add(size)
                    .ok_or(FileParseError::ValueTooLarge)?;
                check_metadata(&tree.root, tree.offset, end, &pe.buffer)?;
                Self::import(pe, &tree.root, tree.offset)
            }
            None => Ok(Self::default()),
        }
    }
    fn import(pe: &PE, node: &ResourceDirectoryNode, base: usize) -> Result<Self, FileParseError> {
        let mut result = Self {
            characteristics: node.header.characteristics.value,
            time_date_stamp: node.header.time_date_stamp.value,
            major_version: node.header.major_version.value,
            minor_version: node.header.minor_version.value,
            entries: Vec::new(),
        };
        for entry in &node.entries {
            let (raw, child) = match entry {
                ResourceEntry::Directory {
                    entry, directory, ..
                } => (
                    entry,
                    ResourceNode::Directory(Self::import(pe, directory, base)?),
                ),
                ResourceEntry::Data { entry, data, .. } => (
                    entry,
                    ResourceNode::Data(ResourceData {
                        bytes: data.payload(pe)?.to_vec(),
                        code_page: data.code_page.value,
                        reserved: data.reserved.value,
                    }),
                ),
            };
            let key = if raw.name_or_id.value & 0x8000_0000 != 0 {
                ResourceKey::Name(raw.name_utf16(&pe.buffer, base)?)
            } else {
                ResourceKey::Id(raw.name_or_id.value)
            };
            if result.entries.iter().any(|(existing, _)| existing == &key) {
                return Err(FileParseError::InvalidFileFormat);
            }
            result.entries.push((key, child));
        }
        Ok(result)
    }
    /// Finds a node by a path of keys.
    pub fn get(&self, path: &[ResourceKey]) -> Option<&ResourceNode> {
        let (key, tail) = path.split_first()?;
        let node = &self.entries.iter().find(|(k, _)| k == key)?.1;
        if tail.is_empty() {
            Some(node)
        } else {
            match node {
                ResourceNode::Directory(d) => d.get(tail),
                _ => None,
            }
        }
    }
    fn parent_mut(
        &mut self,
        path: &[ResourceKey],
    ) -> Result<(&mut Self, ResourceKey), FileParseError> {
        let (last, parents) = path.split_last().ok_or(FileParseError::InvalidFileFormat)?;
        let mut dir = self;
        for key in parents {
            dir = match &mut dir
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
        Ok((dir, last.clone()))
    }
    /// Inserts at an existing parent; duplicate keys are rejected.
    pub fn insert(
        &mut self,
        path: &[ResourceKey],
        node: ResourceNode,
    ) -> Result<(), FileParseError> {
        let (dir, key) = self.parent_mut(path)?;
        if dir.entries.iter().any(|(k, _)| k == &key) {
            return Err(FileParseError::InvalidFileFormat);
        }
        dir.entries.push((key, node));
        Ok(())
    }
    /// Replaces an existing node, returning its previous value.
    pub fn replace(
        &mut self,
        path: &[ResourceKey],
        node: ResourceNode,
    ) -> Result<ResourceNode, FileParseError> {
        let (dir, key) = self.parent_mut(path)?;
        let existing = &mut dir
            .entries
            .iter_mut()
            .find(|(k, _)| k == &key)
            .ok_or(FileParseError::InvalidFileFormat)?
            .1;
        Ok(core::mem::replace(existing, node))
    }
    /// Removes an existing node.
    pub fn remove(&mut self, path: &[ResourceKey]) -> Result<ResourceNode, FileParseError> {
        let (dir, key) = self.parent_mut(path)?;
        let i = dir
            .entries
            .iter()
            .position(|(k, _)| k == &key)
            .ok_or(FileParseError::InvalidFileFormat)?;
        Ok(dir.entries.remove(i).1)
    }
    /// Renames a node without replacing a destination.
    pub fn rename(
        &mut self,
        path: &[ResourceKey],
        new_key: ResourceKey,
    ) -> Result<(), FileParseError> {
        let (dir, key) = self.parent_mut(path)?;
        if new_key != key && dir.entries.iter().any(|(k, _)| k == &new_key) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let entry = dir
            .entries
            .iter_mut()
            .find(|(k, _)| k == &key)
            .ok_or(FileParseError::InvalidFileFormat)?;
        entry.0 = new_key;
        Ok(())
    }
    /// Serializes a canonical tree with payload RVAs relative to `section_rva`.
    pub fn serialize(&self, section_rva: u32) -> Result<Vec<u8>, FileParseError> {
        let mut bytes = Vec::new();
        emit(self, section_rva, &mut bytes, 0)?;
        Ok(bytes)
    }
}
fn reserve(out: &mut Vec<u8>, size: usize) -> Result<usize, FileParseError> {
    let pos = out.len();
    let end = pos.checked_add(size).ok_or(FileParseError::ValueTooLarge)?;
    if end > 0x7fff_ffff {
        return Err(FileParseError::ValueTooLarge);
    }
    out.try_reserve(size)
        .map_err(|_| FileParseError::ValueTooLarge)?;
    out.resize(end, 0);
    Ok(pos)
}
fn put(out: &mut [u8], pos: usize, v: u32) {
    out[pos..pos + 4].copy_from_slice(&v.to_le_bytes());
}
fn align(out: &mut Vec<u8>) -> Result<(), FileParseError> {
    reserve(out, (4 - out.len() % 4) % 4)?;
    Ok(())
}
fn emit(
    dir: &ResourceDirectoryOwned,
    rva: u32,
    out: &mut Vec<u8>,
    depth: usize,
) -> Result<usize, FileParseError> {
    if depth >= 256 {
        return Err(FileParseError::InvalidFileFormat);
    }
    let mut entries: Vec<_> = dir.entries.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    if entries.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(FileParseError::InvalidFileFormat);
    }
    let named = entries
        .iter()
        .filter(|(k, _)| matches!(k, ResourceKey::Name(_)))
        .count();
    let ids = entries.len() - named;
    let nc = u16::try_from(named).map_err(|_| FileParseError::ValueTooLarge)?;
    let ic = u16::try_from(ids).map_err(|_| FileParseError::ValueTooLarge)?;
    align(out)?;
    let start = reserve(out, 16 + entries.len() * 8)?;
    put(out, start, dir.characteristics);
    put(out, start + 4, dir.time_date_stamp);
    out[start + 8..start + 10].copy_from_slice(&dir.major_version.to_le_bytes());
    out[start + 10..start + 12].copy_from_slice(&dir.minor_version.to_le_bytes());
    out[start + 12..start + 14].copy_from_slice(&nc.to_le_bytes());
    out[start + 14..start + 16].copy_from_slice(&ic.to_le_bytes());
    for (i, (key, node)) in entries.into_iter().enumerate() {
        let key_value = match key {
            ResourceKey::Id(id) => {
                if id & 0x8000_0000 != 0 {
                    return Err(FileParseError::ValueTooLarge);
                }
                *id
            }
            ResourceKey::Name(units) => {
                align(out)?;
                let len = u16::try_from(units.len()).map_err(|_| FileParseError::ValueTooLarge)?;
                let pos = reserve(out, 2 + units.len() * 2)?;
                out[pos..pos + 2].copy_from_slice(&len.to_le_bytes());
                for (j, u) in units.iter().enumerate() {
                    out[pos + 2 + j * 2..pos + 4 + j * 2].copy_from_slice(&u.to_le_bytes());
                }
                pos as u32 | 0x8000_0000
            }
        };
        let target = match node {
            ResourceNode::Directory(d) => emit(d, rva, out, depth + 1)? as u32 | 0x8000_0000,
            ResourceNode::Data(d) => {
                align(out)?;
                let rec = reserve(out, 16)?;
                let pos = reserve(out, d.bytes.len())?;
                out[pos..pos + d.bytes.len()].copy_from_slice(&d.bytes);
                put(
                    out,
                    rec,
                    rva.checked_add(pos as u32)
                        .ok_or(FileParseError::ValueTooLarge)?,
                );
                put(
                    out,
                    rec + 4,
                    u32::try_from(d.bytes.len()).map_err(|_| FileParseError::ValueTooLarge)?,
                );
                put(out, rec + 8, d.code_page);
                put(out, rec + 12, d.reserved);
                rec as u32
            }
        };
        put(out, start + 16 + i * 8, key_value);
        put(out, start + 20 + i * 8, target);
    }
    Ok(start)
}
/// Opaque manifest payload; UTF-8 decoding is optional and checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest(pub Vec<u8>);
impl Manifest {
    pub fn utf8(&self) -> Result<&str, core::str::Utf8Error> {
        core::str::from_utf8(&self.0)
    }
    pub fn from_utf8(text: &str) -> Self {
        Self(text.as_bytes().to_vec())
    }
}
impl super::ResourceDirectoryEntry {
    /// Returns exact name units, without lossy Unicode decoding.
    pub fn name_utf16(&self, buffer: &[u8], base: usize) -> Result<Vec<u16>, FileParseError> {
        if self.name_or_id.value & 0x8000_0000 == 0 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let pos = base
            .checked_add((self.name_or_id.value & 0x7fff_ffff) as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        let len = crate::utils::extract_u16(buffer, pos)? as usize;
        let start = pos.checked_add(2).ok_or(FileParseError::BufferOverflow)?;
        let end = start
            .checked_add(len * 2)
            .ok_or(FileParseError::BufferOverflow)?;
        Ok(buffer
            .get(start..end)
            .ok_or(FileParseError::BufferOverflow)?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect())
    }
}
impl super::ResourceDataEntry {
    /// Borrows the complete file-backed payload, rejecting virtual tails and cross-section extents.
    pub fn payload<'a>(&self, pe: &'a PE) -> Result<&'a [u8], FileParseError> {
        let rva = self.offset_to_data.value;
        let size = self.size.value;
        let end = rva.checked_add(size).ok_or(FileParseError::ValueTooLarge)?;
        for s in &pe.sections {
            let begin = s.virtual_address.value;
            let limit = begin
                .checked_add(s.size_of_raw_data.value)
                .ok_or(FileParseError::ValueTooLarge)?;
            if rva >= begin && end <= limit && (rva < limit || size == 0) {
                let pos = (s.pointer_to_raw_data.value as usize)
                    .checked_add((rva - begin) as usize)
                    .ok_or(FileParseError::ValueTooLarge)?;
                let end = pos
                    .checked_add(size as usize)
                    .ok_or(FileParseError::ValueTooLarge)?;
                return pe
                    .buffer
                    .get(pos..end)
                    .ok_or(FileParseError::BufferOverflow);
            }
        }
        Err(FileParseError::BufferOverflow)
    }
}

fn check_metadata(
    node: &ResourceDirectoryNode,
    base: usize,
    end: usize,
    buffer: &[u8],
) -> Result<(), FileParseError> {
    let extent = node
        .offset
        .checked_add(16)
        .and_then(|n| n.checked_add(node.entries.len() * 8))
        .ok_or(FileParseError::ValueTooLarge)?;
    if node.offset < base || extent > end {
        return Err(FileParseError::BufferOverflow);
    }
    for item in &node.entries {
        let entry = match item {
            ResourceEntry::Directory {
                entry, directory, ..
            } => {
                check_metadata(directory, base, end, buffer)?;
                entry
            }
            ResourceEntry::Data { entry, data, .. } => {
                if data.offset_to_data.offset < base
                    || data
                        .offset_to_data
                        .offset
                        .checked_add(16)
                        .is_none_or(|n| n > end)
                {
                    return Err(FileParseError::BufferOverflow);
                }
                entry
            }
        };
        if entry.name_or_id.value & 0x8000_0000 != 0 {
            let pos = base
                .checked_add((entry.name_or_id.value & 0x7fff_ffff) as usize)
                .ok_or(FileParseError::ValueTooLarge)?;
            let len = crate::utils::extract_u16(buffer, pos)? as usize;
            if pos.checked_add(2 + len * 2).is_none_or(|n| n > end) {
                return Err(FileParseError::BufferOverflow);
            }
        }
    }
    Ok(())
}
