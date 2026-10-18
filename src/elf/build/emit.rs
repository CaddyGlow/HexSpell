use super::*;
const BASE: u64 = 0x400000;
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or(FileParseError::ValueTooLarge)
}
fn align(value: u64, alignment: u64) -> Result<u64> {
    Ok(add(value, alignment - 1)? & !(alignment - 1))
}
fn usize_of(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| FileParseError::ValueTooLarge)
}
fn put(out: &mut [u8], offset: usize, value: u64, size: usize) {
    out[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
}
fn append(out: &mut Vec<u8>, value: u64, size: usize) {
    out.extend_from_slice(&value.to_le_bytes()[..size]);
}
fn string(table: &mut Vec<u8>, name: &str) -> Result<u64> {
    let offset = u32::try_from(table.len()).map_err(|_| FileParseError::ValueTooLarge)?;
    table.extend_from_slice(name.as_bytes());
    table.push(0);
    Ok(offset as u64)
}
struct Sh {
    name: u64,
    kind: u64,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u64,
    info: u64,
    alignment: u64,
    entry_size: u64,
}
impl Sh {
    fn write(&self, out: &mut Vec<u8>) {
        for (value, size) in [
            (self.name, 4),
            (self.kind, 4),
            (self.flags, 8),
            (self.address, 8),
            (self.offset, 8),
            (self.size, 8),
            (self.link, 4),
            (self.info, 4),
            (self.alignment, 8),
            (self.entry_size, 8),
        ] {
            append(out, value, size);
        }
    }
}
struct Ph {
    flags: u64,
    offset: u64,
    address: u64,
    file_size: u64,
    memory_size: u64,
}
pub(super) fn build(builder: &ElfBuilder) -> Result<(ELF, LayoutReport)> {
    let base = if builder.kind == ImageKind::Executable {
        BASE
    } else {
        0
    };
    if let Some(entry_index) = builder.entry {
        let entry_symbol = &builder.symbols[entry_index];
        let entry_section = &builder.sections[entry_symbol.section];
        let entry_segment = entry_section
            .segment
            .ok_or(FileParseError::InvalidFileFormat)?;
        if !builder.segments[entry_segment].execute
            || entry_symbol.offset >= entry_section.spec.data.len() as u64
        {
            return Err(FileParseError::InvalidFileFormat);
        }
    } else if builder.kind != ImageKind::SharedObject {
        return Err(FileParseError::InvalidFileFormat);
    }
    // Reserve the complete program-header table before placing initialized bytes.
    let ph_count = builder
        .segments
        .len()
        .checked_add(3 + builder.extra_programs.len())
        .ok_or(FileParseError::ValueTooLarge)?;
    if ph_count >= 0xffff || builder.sections.len() >= 0xff00 - 4 {
        return Err(FileParseError::ValueTooLarge);
    }
    let header_size = add(
        64,
        (ph_count as u64)
            .checked_mul(56)
            .ok_or(FileParseError::ValueTooLarge)?,
    )?;
    let mut file_cursor = header_size;
    let mut virtual_cursor = align(header_size, 4096)?;
    let mut placements: Vec<Option<SectionLayout>> = vec![None; builder.sections.len()];
    let mut offsets = vec![0u64; builder.sections.len()];
    let mut programs = vec![Ph {
        flags: 4,
        offset: 0,
        address: base,
        file_size: header_size,
        memory_size: header_size,
    }];
    for (index, segment) in builder.segments.iter().enumerate() {
        file_cursor = align(file_cursor, 4096)?;
        let start_file = file_cursor;
        let start_virtual = virtual_cursor;
        let mut relative = 0;
        let mut file_size = 0;
        let mut zero_fill_seen = false;
        for (section_index, section) in builder
            .sections
            .iter()
            .enumerate()
            .filter(|(_, s)| s.segment == Some(index))
        {
            let spec = &section.spec;
            relative = align(relative, spec.alignment)?;
            let zero_fill = spec.is_zero_fill;
            if !zero_fill && zero_fill_seen {
                return Err(FileParseError::UnsupportedFeature(
                    "initialized section after zero-fill in ELF segment".into(),
                ));
            }
            zero_fill_seen |= zero_fill;
            let size = if zero_fill {
                spec.zero_fill
            } else {
                spec.data.len() as u64
            };
            offsets[section_index] = add(start_file, relative)?;
            placements[section_index] = Some(SectionLayout {
                section: SectionId {
                    owner: builder.owner.clone(),
                    index: section_index,
                },
                file_offset: if zero_fill {
                    None
                } else {
                    Some(offsets[section_index])
                },
                virtual_address: Some(add(base, add(start_virtual, relative)?)?),
                size,
            });
            relative = add(relative, size)?;
            if !zero_fill {
                file_size = relative;
            }
        }
        file_cursor = add(start_file, file_size)?;
        virtual_cursor = align(add(start_virtual, relative)?, 4096)?;
        // Empty segments are invalid loader specifications, rather than aliases of the next mapping.
        if relative == 0 {
            return Err(FileParseError::InvalidFileFormat);
        }
        programs.push(Ph {
            flags: (u64::from(segment.read) * 4)
                | (u64::from(segment.write) * 2)
                | u64::from(segment.execute),
            offset: start_file,
            address: add(base, start_virtual)?,
            file_size,
            memory_size: relative,
        });
    }
    for (index, section) in builder
        .sections
        .iter()
        .enumerate()
        .filter(|(_, s)| s.segment.is_none())
    {
        file_cursor = align(file_cursor, section.spec.alignment)?;
        offsets[index] = file_cursor;
        placements[index] = Some(SectionLayout {
            section: SectionId {
                owner: builder.owner.clone(),
                index,
            },
            file_offset: Some(file_cursor),
            virtual_address: None,
            size: section.spec.data.len() as u64,
        });
        file_cursor = add(file_cursor, section.spec.data.len() as u64)?;
    }
    let placements: Vec<SectionLayout> = placements
        .into_iter()
        .map(|p| p.ok_or(FileParseError::InvalidFileFormat))
        .collect::<Result<_>>()?;
    let entry = if let Some(index) = builder.entry {
        let symbol = &builder.symbols[index];
        add(
            placements[symbol.section]
                .virtual_address
                .ok_or(FileParseError::InvalidFileFormat)?,
            symbol.offset,
        )?
    } else {
        0
    };
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize_of(file_cursor)?)
        .map_err(|_| FileParseError::ValueTooLarge)?;
    bytes.resize(usize_of(file_cursor)?, 0);
    for (index, section) in builder.sections.iter().enumerate() {
        if !section.spec.data.is_empty() {
            let start = usize_of(offsets[index])?;
            bytes[start..start + section.spec.data.len()].copy_from_slice(&section.spec.data);
        }
    }
    for fixup in &builder.fixups {
        let symbol = &builder.symbols[fixup.target];
        let target = add(
            placements[symbol.section]
                .virtual_address
                .ok_or(FileParseError::InvalidFileFormat)?,
            symbol.offset,
        )?;
        let value = i128::from(target) + i128::from(fixup.addend);
        let source_file = usize_of(add(offsets[fixup.section], fixup.offset)?)?;
        match fixup.kind {
            FixupKind::Absolute64 => put(
                &mut bytes,
                source_file,
                u64::try_from(value).map_err(|_| FileParseError::ValueTooLarge)?,
                8,
            ),
            FixupKind::Absolute32 => put(
                &mut bytes,
                source_file,
                u32::try_from(value).map_err(|_| FileParseError::ValueTooLarge)? as u64,
                4,
            ),
            FixupKind::PcRelative32 => {
                let origin = add(
                    placements[fixup.section]
                        .virtual_address
                        .ok_or(FileParseError::InvalidFileFormat)?,
                    add(fixup.offset, 4)?,
                )?;
                let displacement = i32::try_from(value - i128::from(origin))
                    .map_err(|_| FileParseError::ValueTooLarge)?;
                put(&mut bytes, source_file, displacement as u32 as u64, 4);
            }
        }
    }
    let mut sh_offset = 0;
    let mut sh_count = 0;
    let mut sh_string_index = 0;
    if builder.section_table {
        let mut names = vec![0];
        let mut headers = Vec::new();
        for (index, section) in builder.sections.iter().enumerate() {
            let segment = section.segment.map(|i| builder.segments[i]);
            headers.push(Sh {
                name: string(&mut names, &section.spec.name)?,
                kind: if section.spec.is_zero_fill { 8 } else { 1 },
                flags: segment.map_or(0, |s| {
                    2 | if s.write { 1 } else { 0 } | if s.execute { 4 } else { 0 }
                }),
                address: placements[index].virtual_address.unwrap_or(0),
                offset: offsets[index],
                size: placements[index].size,
                link: 0,
                info: 0,
                alignment: section.spec.alignment,
                entry_size: 0,
            });
        }
        if !builder.symbols.is_empty() {
            let mut strings = vec![0];
            let mut symbols = vec![0; 24];
            let mut local_count = 1;
            for binding in [Binding::Local, Binding::Global, Binding::Weak] {
                for symbol in builder.symbols.iter().filter(|s| s.binding == binding) {
                    append(&mut symbols, string(&mut strings, &symbol.name)?, 4);
                    append(
                        &mut symbols,
                        if binding == Binding::Local {
                            local_count += 1;
                            0
                        } else {
                            if binding == Binding::Weak {
                                0x20
                            } else {
                                0x10
                            }
                        },
                        1,
                    );
                    append(
                        &mut symbols,
                        match symbol.visibility {
                            Visibility::Default => 0,
                            Visibility::Hidden => 2,
                            Visibility::Protected => 3,
                        },
                        1,
                    );
                    append(&mut symbols, (symbol.section + 1) as u64, 2);
                    append(
                        &mut symbols,
                        add(
                            placements[symbol.section].virtual_address.unwrap_or(0),
                            symbol.offset,
                        )?,
                        8,
                    );
                    append(&mut symbols, symbol.size, 8);
                }
            }
            while bytes.len() % 8 != 0 {
                bytes.push(0);
            }
            let sym_offset = bytes.len() as u64;
            bytes.extend_from_slice(&symbols);
            let string_offset = bytes.len() as u64;
            bytes.extend_from_slice(&strings);
            let sym_index = headers.len() + 1;
            headers.push(Sh {
                name: string(&mut names, ".symtab")?,
                kind: 2,
                flags: 0,
                address: 0,
                offset: sym_offset,
                size: symbols.len() as u64,
                link: (sym_index + 1) as u64,
                info: local_count,
                alignment: 8,
                entry_size: 24,
            });
            headers.push(Sh {
                name: string(&mut names, ".strtab")?,
                kind: 3,
                flags: 0,
                address: 0,
                offset: string_offset,
                size: strings.len() as u64,
                link: 0,
                info: 0,
                alignment: 1,
                entry_size: 0,
            });
        }
        sh_string_index = headers.len() + 1;
        let names_name = string(&mut names, ".shstrtab")?;
        let names_offset = bytes.len() as u64;
        bytes.extend_from_slice(&names);
        headers.push(Sh {
            name: names_name,
            kind: 3,
            flags: 0,
            address: 0,
            offset: names_offset,
            size: names.len() as u64,
            link: 0,
            info: 0,
            alignment: 1,
            entry_size: 0,
        });
        while bytes.len() % 8 != 0 {
            bytes.push(0);
        }
        sh_offset = bytes.len() as u64;
        sh_count = headers.len() + 1;
        bytes.extend_from_slice(&[0; 64]);
        for header in headers {
            header.write(&mut bytes);
        }
    }
    bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    for (offset, value, size) in [
        (
            16,
            if builder.kind == ImageKind::Executable {
                2
            } else {
                3
            },
            2,
        ),
        (18, 62, 2),
        (20, 1, 4),
        (24, entry, 8),
        (32, 64, 8),
        (40, sh_offset, 8),
        (52, 64, 2),
        (54, 56, 2),
        (56, ph_count as u64, 2),
        (58, if builder.section_table { 64 } else { 0 }, 2),
        (60, sh_count as u64, 2),
        (62, sh_string_index as u64, 2),
    ] {
        put(&mut bytes, offset, value, size);
    }
    // PT_PHDR and PT_INTERP must precede loadable segments. PT_PHDR also
    // supplies the dynamic loader with the executable's relocation base.
    for (offset, value, size) in [
        (0, 6, 4),
        (4, 4, 4),
        (8, 64, 8),
        (16, add(base, 64)?, 8),
        (24, add(base, 64)?, 8),
        (32, (ph_count as u64) * 56, 8),
        (40, (ph_count as u64) * 56, 8),
        (48, 8, 8),
    ] {
        put(&mut bytes, 64 + offset, value, size);
    }
    let interpreter_count = builder
        .extra_programs
        .iter()
        .filter(|(kind, _)| *kind == 3)
        .count();
    for (index, program) in programs.iter().enumerate() {
        let start = 64 + (1 + interpreter_count + index) * 56;
        for (offset, value, size) in [
            (0, 1, 4),
            (4, program.flags, 4),
            (8, program.offset, 8),
            (16, program.address, 8),
            (24, program.address, 8),
            (32, program.file_size, 8),
            (40, program.memory_size, 8),
            (48, 4096, 8),
        ] {
            put(&mut bytes, start + offset, value, size);
        }
    }
    let mut interpreter_index = 0;
    let mut other_index = 0;
    for (kind, section_index) in &builder.extra_programs {
        let section = &placements[*section_index];
        let index = if *kind == 3 {
            interpreter_index += 1;
            interpreter_index
        } else {
            let current = 1 + interpreter_count + programs.len() + other_index;
            other_index += 1;
            current
        };
        let start = 64 + index * 56;
        for (offset, value, size) in [
            (0, *kind, 4),
            (4, if *kind == 2 { 6 } else { 4 }, 4),
            (
                8,
                section
                    .file_offset
                    .ok_or(FileParseError::InvalidFileFormat)?,
                8,
            ),
            (
                16,
                section
                    .virtual_address
                    .ok_or(FileParseError::InvalidFileFormat)?,
                8,
            ),
            (
                24,
                section
                    .virtual_address
                    .ok_or(FileParseError::InvalidFileFormat)?,
                8,
            ),
            (32, section.size, 8),
            (40, section.size, 8),
            (
                48,
                if *kind == 2 {
                    8
                } else if *kind == 7 {
                    builder.sections[*section_index].spec.alignment
                } else {
                    1
                },
                8,
            ),
        ] {
            put(&mut bytes, start + offset, value, size);
        }
    }
    let stack = 64 + (ph_count - 1) * 56;
    put(&mut bytes, stack, 0x6474e551, 4);
    put(&mut bytes, stack + 4, 6, 4);
    put(&mut bytes, stack + 48, 16, 8);
    let image = ELF::from_buffer(bytes)?;
    Ok((
        image,
        LayoutReport {
            image_base: base,
            entry,
            sections: placements,
            segments: programs
                .iter()
                .enumerate()
                .skip(1)
                .map(|(index, p)| SegmentLayout {
                    segment: SegmentId {
                        owner: builder.owner.clone(),
                        index: index - 1,
                    },
                    file_offset: p.offset,
                    virtual_address: p.address,
                    file_size: p.file_size,
                    memory_size: p.memory_size,
                })
                .collect(),
        },
    ))
}
