//! GNU/Solaris ELF symbol version tables (LSB Core 5.0 section 10.7).
use super::*;
struct Definition {
    index: u16,
    name: u32,
    hash: u32,
}
struct Requirement {
    index: u16,
    name: u32,
    library: u32,
    hash: u32,
}
pub(super) struct Versions {
    symbols: Vec<u8>,
    definitions: Vec<Definition>,
    requirements: Vec<Requirement>,
}
pub(super) struct Sections {
    symbols: Option<usize>,
    definitions: Option<usize>,
    requirements: Option<usize>,
}
fn hash(name: &str) -> u32 {
    let mut value = 0u32;
    for byte in name.bytes() {
        value = (value << 4).wrapping_add(u32::from(byte));
        let high = value & 0xf0000000;
        value ^= high >> 24;
        value &= !high;
    }
    value
}
pub(super) fn prepare(
    source: &ElfBuilder,
    exports: &[&Symbol],
    strings: &mut Vec<u8>,
) -> Result<Versions> {
    let mut definitions = Vec::new();
    let mut requirements = Vec::new();
    let mut names: Vec<(String, Option<String>, u16)> = Vec::new();
    let mut symbols = vec![0, 0];
    for symbol in exports {
        let index = if let Some(version) = &symbol.version {
            if let Some((_, _, index)) = names
                .iter()
                .find(|(v, library, _)| v == version && library.is_none())
            {
                *index
            } else {
                let index =
                    u16::try_from(names.len() + 2).map_err(|_| FileParseError::ValueTooLarge)?;
                if index >= 0x8000 {
                    return Err(FileParseError::ValueTooLarge);
                }
                names.push((version.clone(), None, index));
                definitions.push(Definition {
                    index,
                    name: string(strings, version)?,
                    hash: hash(version),
                });
                index
            }
        } else {
            1
        };
        symbols.extend_from_slice(&index.to_le_bytes());
    }
    for ((library, _, _), version) in source.imports.iter().zip(&source.import_versions) {
        let index = if let Some(version) = version {
            if let Some((_, _, index)) = names
                .iter()
                .find(|(v, lib, _)| v == version && lib.as_deref() == Some(library.as_str()))
            {
                *index
            } else {
                let index =
                    u16::try_from(names.len() + 2).map_err(|_| FileParseError::ValueTooLarge)?;
                if index >= 0x8000 {
                    return Err(FileParseError::ValueTooLarge);
                }
                names.push((version.clone(), Some(library.clone()), index));
                requirements.push(Requirement {
                    index,
                    name: string(strings, version)?,
                    library: string(strings, library)?,
                    hash: hash(version),
                });
                index
            }
        } else {
            1
        };
        symbols.extend_from_slice(&index.to_le_bytes());
    }
    Ok(Versions {
        symbols,
        definitions,
        requirements,
    })
}
impl Versions {
    pub(super) fn tag_count(&self) -> usize {
        if self.definitions.is_empty() && self.requirements.is_empty() {
            0
        } else {
            1 + 2 * usize::from(!self.definitions.is_empty())
                + 2 * usize::from(!self.requirements.is_empty())
        }
    }
    pub(super) fn emit(&self, builder: &mut ElfBuilder, segment: &SegmentId) -> Result<Sections> {
        let mut sections = Sections {
            symbols: None,
            definitions: None,
            requirements: None,
        };
        if self.tag_count() == 0 {
            return Ok(sections);
        }
        sections.symbols = Some(generated(
            builder,
            segment,
            ".gnu.version",
            self.symbols.clone(),
            2,
        )?);
        if !self.definitions.is_empty() {
            let mut bytes = Vec::new();
            for (i, d) in self.definitions.iter().enumerate() {
                for (value, width) in [
                    (1, 2),
                    (0, 2),
                    (u64::from(d.index), 2),
                    (1, 2),
                    (u64::from(d.hash), 4),
                    (20, 4),
                    (
                        if i + 1 == self.definitions.len() {
                            0
                        } else {
                            28
                        },
                        4,
                    ),
                    (u64::from(d.name), 4),
                    (0, 4),
                ] {
                    push(&mut bytes, value, width);
                }
            }
            sections.definitions = Some(generated(builder, segment, ".gnu.version_d", bytes, 4)?);
        }
        if !self.requirements.is_empty() {
            let mut bytes = Vec::new();
            for (i, r) in self.requirements.iter().enumerate() {
                for (value, width) in [
                    (1, 2),
                    (1, 2),
                    (u64::from(r.library), 4),
                    (16, 4),
                    (
                        if i + 1 == self.requirements.len() {
                            0
                        } else {
                            32
                        },
                        4,
                    ),
                    (u64::from(r.hash), 4),
                    (0, 2),
                    (u64::from(r.index), 2),
                    (u64::from(r.name), 4),
                    (0, 4),
                ] {
                    push(&mut bytes, value, width);
                }
            }
            sections.requirements = Some(generated(builder, segment, ".gnu.version_r", bytes, 4)?);
        }
        Ok(sections)
    }
    pub(super) fn tags(
        &self,
        sections: &Sections,
        layout: &LayoutReport,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        for (section, tag, count) in [
            (sections.symbols, 0x6ffffff0, None),
            (
                sections.definitions,
                0x6ffffffc,
                Some(self.definitions.len()),
            ),
            (
                sections.requirements,
                0x6ffffffe,
                Some(self.requirements.len()),
            ),
        ] {
            if let Some(section) = section {
                push(out, tag, 8);
                push(out, address(layout, section)?, 8);
                if let Some(count) = count {
                    push(out, tag + 1, 8);
                    push(out, count as u64, 8);
                }
            }
        }
        Ok(())
    }
    pub(super) fn patch_sections(
        &self,
        sections: &Sections,
        strings: usize,
        symbols: usize,
        image: &mut ELF,
        table: usize,
    ) {
        for (section, kind, link, info, size) in [
            (sections.symbols, 0x6fffffff, symbols, 0, 2),
            (
                sections.definitions,
                0x6ffffffd,
                strings,
                self.definitions.len(),
                0,
            ),
            (
                sections.requirements,
                0x6ffffffe,
                strings,
                self.requirements.len(),
                0,
            ),
        ] {
            if let Some(section) = section {
                let offset = table + (section + 1) * 64;
                image.buffer[offset + 4..offset + 8].copy_from_slice(&(kind as u32).to_le_bytes());
                image.buffer[offset + 40..offset + 44]
                    .copy_from_slice(&((link + 1) as u32).to_le_bytes());
                image.buffer[offset + 44..offset + 48]
                    .copy_from_slice(&(info as u32).to_le_bytes());
                image.buffer[offset + 56..offset + 64]
                    .copy_from_slice(&(size as u64).to_le_bytes());
            }
        }
    }
}
