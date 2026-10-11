//! ICO containers and group icon records without bitmap transcoding.
use crate::errors::FileParseError;
use alloc::vec::Vec;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IconImage {
    pub width: u8,
    pub height: u8,
    pub color_count: u8,
    pub reserved: u8,
    pub planes: u16,
    pub bit_count: u16,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Icon {
    pub images: Vec<IconImage>,
}
impl Icon {
    pub fn parse(bytes: &[u8]) -> Result<Self, FileParseError> {
        if crate::utils::extract_u16(bytes, 0)? != 0 || crate::utils::extract_u16(bytes, 2)? != 1 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let count = crate::utils::extract_u16(bytes, 4)? as usize;
        let table_end = 6 + count * 16;
        if table_end > bytes.len() {
            return Err(FileParseError::BufferOverflow);
        }
        let mut images = Vec::with_capacity(count);
        for i in 0..count {
            let pos = 6 + i * 16;
            let size = crate::utils::extract_u32(bytes, pos + 8)? as usize;
            let offset = crate::utils::extract_u32(bytes, pos + 12)? as usize;
            if offset < table_end {
                return Err(FileParseError::InvalidFileFormat);
            }
            let end = offset
                .checked_add(size)
                .ok_or(FileParseError::ValueTooLarge)?;
            images.push(IconImage {
                width: bytes[pos],
                height: bytes[pos + 1],
                color_count: bytes[pos + 2],
                reserved: bytes[pos + 3],
                planes: crate::utils::extract_u16(bytes, pos + 4)?,
                bit_count: crate::utils::extract_u16(bytes, pos + 6)?,
                bytes: bytes
                    .get(offset..end)
                    .ok_or(FileParseError::BufferOverflow)?
                    .to_vec(),
            });
        }
        Ok(Self { images })
    }
    pub fn serialize(&self) -> Result<Vec<u8>, FileParseError> {
        let count = u16::try_from(self.images.len()).map_err(|_| FileParseError::ValueTooLarge)?;
        let mut out = alloc::vec![0;6+self.images.len()*16];
        out[2..4].copy_from_slice(&1u16.to_le_bytes());
        out[4..6].copy_from_slice(&count.to_le_bytes());
        for (i, image) in self.images.iter().enumerate() {
            let pos = 6 + i * 16;
            write_header(&mut out[pos..pos + 8], image);
            let size =
                u32::try_from(image.bytes.len()).map_err(|_| FileParseError::ValueTooLarge)?;
            let offset = u32::try_from(out.len()).map_err(|_| FileParseError::ValueTooLarge)?;
            out[pos + 8..pos + 12].copy_from_slice(&size.to_le_bytes());
            out[pos + 12..pos + 16].copy_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&image.bytes);
        }
        Ok(out)
    }
    /// Emits RT_GROUP_ICON bytes for explicitly allocated image IDs.
    pub fn group(&self, ids: &[u16]) -> Result<Vec<u8>, FileParseError> {
        if ids.len() != self.images.len() || ids.contains(&0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let count = u16::try_from(ids.len()).map_err(|_| FileParseError::ValueTooLarge)?;
        let mut out = alloc::vec![0;6+ids.len()*14];
        out[2..4].copy_from_slice(&1u16.to_le_bytes());
        out[4..6].copy_from_slice(&count.to_le_bytes());
        for (i, (image, id)) in self.images.iter().zip(ids).enumerate() {
            let pos = 6 + i * 14;
            write_header(&mut out[pos..pos + 8], image);
            let size =
                u32::try_from(image.bytes.len()).map_err(|_| FileParseError::ValueTooLarge)?;
            out[pos + 8..pos + 12].copy_from_slice(&size.to_le_bytes());
            out[pos + 12..pos + 14].copy_from_slice(&id.to_le_bytes());
        }
        Ok(out)
    }
}
fn write_header(out: &mut [u8], image: &IconImage) {
    out[..4].copy_from_slice(&[image.width, image.height, image.color_count, image.reserved]);
    out[4..6].copy_from_slice(&image.planes.to_le_bytes());
    out[6..8].copy_from_slice(&image.bit_count.to_le_bytes());
}
impl super::ResourceDirectoryOwned {
    /// Adds ICO images using globally unused numeric icon IDs and replaces the selected group.
    /// Old image resources are retained because other groups may share them.
    pub fn set_icon(
        &mut self,
        name: super::ResourceKey,
        language: u32,
        icon: &Icon,
    ) -> Result<Vec<u16>, FileParseError> {
        use super::{ResourceData, ResourceDirectoryOwned, ResourceKey, ResourceNode};
        let mut candidate = self.clone();
        let mut used = alloc::collections::BTreeSet::new();
        if let Some(ResourceNode::Directory(images)) = candidate.get(&[ResourceKey::Id(3)]) {
            for (key, _) in &images.entries {
                if let ResourceKey::Id(id) = key {
                    used.insert(*id);
                }
            }
        }
        let mut ids = Vec::with_capacity(icon.images.len());
        let mut next = 1u32;
        for _ in &icon.images {
            while used.contains(&next) {
                next = next.checked_add(1).ok_or(FileParseError::ValueTooLarge)?;
            }
            let id = u16::try_from(next).map_err(|_| FileParseError::ValueTooLarge)?;
            ids.push(id);
            used.insert(next);
            next += 1;
        }
        let group = icon.group(&ids)?;
        fn directory(
            parent: &mut ResourceDirectoryOwned,
            key: ResourceKey,
        ) -> Result<&mut ResourceDirectoryOwned, FileParseError> {
            if !parent.entries.iter().any(|(k, _)| k == &key) {
                parent.entries.push((
                    key.clone(),
                    ResourceNode::Directory(ResourceDirectoryOwned::default()),
                ));
            }
            match &mut parent
                .entries
                .iter_mut()
                .find(|(k, _)| k == &key)
                .ok_or(FileParseError::InvalidFileFormat)?
                .1
            {
                ResourceNode::Directory(d) => Ok(d),
                _ => Err(FileParseError::InvalidFileFormat),
            }
        }
        for (image, id) in icon.images.iter().zip(&ids) {
            let dir = directory(
                directory(&mut candidate, ResourceKey::Id(3))?,
                ResourceKey::Id(*id as u32),
            )?;
            dir.entries.push((
                ResourceKey::Id(language),
                ResourceNode::Data(ResourceData {
                    bytes: image.bytes.clone(),
                    code_page: 0,
                    reserved: 0,
                }),
            ));
        }
        let dir = directory(directory(&mut candidate, ResourceKey::Id(14))?, name)?;
        let key = ResourceKey::Id(language);
        let data = ResourceNode::Data(ResourceData {
            bytes: group,
            code_page: 0,
            reserved: 0,
        });
        if let Some((_, node)) = dir.entries.iter_mut().find(|(k, _)| k == &key) {
            *node = data;
        } else {
            dir.entries.push((key, data));
        }
        candidate.serialize(0)?;
        *self = candidate;
        Ok(ids)
    }
    /// Reconstructs an ICO from one group and matching-language RT_ICON payloads.
    pub fn icon(&self, name: &super::ResourceKey, language: u32) -> Result<Icon, FileParseError> {
        use super::{ResourceKey, ResourceNode};
        let ResourceNode::Data(group) = self
            .get(&[ResourceKey::Id(14), name.clone(), ResourceKey::Id(language)])
            .ok_or(FileParseError::InvalidFileFormat)?
        else {
            return Err(FileParseError::InvalidFileFormat);
        };
        let bytes = &group.bytes;
        if crate::utils::extract_u16(bytes, 0)? != 0 || crate::utils::extract_u16(bytes, 2)? != 1 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let count = crate::utils::extract_u16(bytes, 4)? as usize;
        if bytes.len() != 6 + count * 14 {
            return Err(FileParseError::BufferOverflow);
        }
        let mut images = Vec::with_capacity(count);
        for i in 0..count {
            let pos = 6 + i * 14;
            let id = crate::utils::extract_u16(bytes, pos + 12)?;
            let ResourceNode::Data(data) = self
                .get(&[
                    ResourceKey::Id(3),
                    ResourceKey::Id(id as u32),
                    ResourceKey::Id(language),
                ])
                .ok_or(FileParseError::InvalidFileFormat)?
            else {
                return Err(FileParseError::InvalidFileFormat);
            };
            if crate::utils::extract_u32(bytes, pos + 8)? as usize != data.bytes.len() {
                return Err(FileParseError::InvalidFileFormat);
            }
            images.push(IconImage {
                width: bytes[pos],
                height: bytes[pos + 1],
                color_count: bytes[pos + 2],
                reserved: bytes[pos + 3],
                planes: crate::utils::extract_u16(bytes, pos + 4)?,
                bit_count: crate::utils::extract_u16(bytes, pos + 6)?,
                bytes: data.bytes.clone(),
            });
        }
        Ok(Icon { images })
    }
}
