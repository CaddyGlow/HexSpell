//! Scoped Linux ELF64 dynamic loader metadata with eager GOT slots and RELA.
mod versions;
use super::*;
fn push(bytes: &mut Vec<u8>, value: u64, width: usize) {
    bytes.extend_from_slice(&value.to_le_bytes()[..width]);
}
fn string(bytes: &mut Vec<u8>, value: &str) -> Result<u32> {
    let offset = u32::try_from(bytes.len()).map_err(|_| FileParseError::ValueTooLarge)?;
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
    Ok(offset)
}
fn generated(
    builder: &mut ElfBuilder,
    segment: &SegmentId,
    name: &str,
    data: Vec<u8>,
    alignment: u64,
) -> Result<usize> {
    let mut spec = SectionSpec::new(name, data);
    spec.alignment = alignment;
    Ok(builder.add_section(Some(segment), spec)?.index)
}
fn address(layout: &LayoutReport, index: usize) -> Result<u64> {
    layout.sections[index]
        .virtual_address
        .ok_or(FileParseError::InvalidFileFormat)
}
fn symbol_address(builder: &ElfBuilder, layout: &LayoutReport, symbol: &Symbol) -> Result<u64> {
    if builder.sections[symbol.section].segment.is_none() {
        return Err(FileParseError::UnsupportedFeature(
            "dynamic export of nonallocated section".into(),
        ));
    }
    address(layout, symbol.section)?
        .checked_add(symbol.offset)
        .ok_or(FileParseError::ValueTooLarge)
}
// Use one policy for explicit pointers and generated lifecycle arrays. Dynamic
// symbol order is all nonlocal definitions in specification order, after STN_UNDEF.
pub(super) fn pointer_relocation(
    builder: &ElfBuilder,
    layout: &LayoutReport,
    symbol_index: usize,
    addend: i64,
) -> Result<(u64, i64)> {
    let symbol = &builder.symbols[symbol_index];
    if symbol.binding != Binding::Local && symbol.visibility == Visibility::Default {
        let index = builder.symbols[..=symbol_index]
            .iter()
            .filter(|symbol| symbol.binding != Binding::Local)
            .count();
        Ok(((index as u64) << 32 | 1, addend)) // R_X86_64_64.
    } else {
        let target = i128::from(symbol_address(builder, layout, symbol)?) + i128::from(addend);
        let target = u64::try_from(target).map_err(|_| FileParseError::ValueTooLarge)?;
        Ok((
            8,
            i64::try_from(target).map_err(|_| FileParseError::ValueTooLarge)?,
        ))
    }
}

pub(super) fn build(source: &ElfBuilder) -> Result<(ELF, LayoutReport)> {
    if source.kind != ImageKind::SharedObject
        && (!source.initializers.is_empty() || !source.finalizers.is_empty())
    {
        return Err(FileParseError::UnsupportedFeature("ELF initializer arrays require shared-object loader lifecycle; PIE requires caller CRT".into()));
    }
    if source.kind == ImageKind::Pie && source.interpreter.is_none() {
        return Err(FileParseError::UnsupportedFeature(
            "PIE requires an explicit Linux interpreter".into(),
        ));
    }
    if source.kind == ImageKind::SharedObject && source.interpreter.is_some() {
        return Err(FileParseError::InvalidFileFormat);
    }
    if source
        .fixups
        .iter()
        .any(|f| f.kind == FixupKind::Absolute32)
    {
        return Err(FileParseError::UnsupportedFeature(
            "32-bit absolute fixup in dynamically relocated image".into(),
        ));
    }
    let exports: Vec<_> = source
        .symbols
        .iter()
        .filter(|s| s.binding != Binding::Local)
        .collect();
    let symbol_count = 1usize
        .checked_add(exports.len())
        .and_then(|v| v.checked_add(source.imports.len()))
        .ok_or(FileParseError::ValueTooLarge)?;
    let symbol_count_u32 =
        u32::try_from(symbol_count).map_err(|_| FileParseError::ValueTooLarge)?;
    let mut candidate = ElfBuilder {
        owner: source.owner.clone(),
        segments: source.segments.clone(),
        sections: source.sections.clone(),
        symbols: source.symbols.clone(),
        fixups: source
            .fixups
            .iter()
            .filter(|f| f.kind != FixupKind::Absolute64)
            .cloned()
            .collect(),
        entry: source.entry,
        section_table: source.section_table,
        kind: source.kind,
        interpreter: source.interpreter.clone(),
        soname: source.soname.clone(),
        runpath: source.runpath.clone(),
        imports: source.imports.clone(),
        import_versions: source.import_versions.clone(),
        extra_programs: Vec::new(),
        initializers: source.initializers.clone(),
        finalizers: source.finalizers.clone(),
        tls: source.tls,
        tls_slots: source.tls_slots.clone(),
        unwind: source.unwind.clone(),
    };
    let runtime = runtime::prepare(&mut candidate)?;
    let ro = candidate.add_segment(SegmentSpec::R)?;
    let rw = candidate.add_segment(SegmentSpec::RW)?;
    if let Some(interpreter) = &source.interpreter {
        let mut bytes = interpreter.as_bytes().to_vec();
        bytes.push(0);
        let section = generated(&mut candidate, &ro, ".interp", bytes, 1)?;
        candidate.extra_programs.push((3, section));
    }
    let mut strings = vec![0];
    let export_names: Vec<u32> = exports
        .iter()
        .map(|s| string(&mut strings, &s.name))
        .collect::<Result<_>>()?;
    let import_names: Vec<u32> = source
        .imports
        .iter()
        .map(|(_, name, _)| string(&mut strings, name))
        .collect::<Result<_>>()?;
    let mut needed = Vec::new();
    let mut libraries: Vec<&str> = Vec::new();
    for (library, _, _) in &source.imports {
        if !libraries.contains(&library.as_str()) {
            libraries.push(library);
            needed.push(string(&mut strings, library)?);
        }
    }
    let soname = source
        .soname
        .as_ref()
        .map(|s| string(&mut strings, s))
        .transpose()?;
    let runpath = source
        .runpath
        .as_ref()
        .map(|s| string(&mut strings, s))
        .transpose()?;
    let versions = versions::prepare(source, &exports, &mut strings)?;
    let strings_len = strings.len();
    let dynstr = generated(&mut candidate, &ro, ".dynstr", strings, 1)?;
    let dynsym = generated(
        &mut candidate,
        &ro,
        ".dynsym",
        vec![
            0;
            symbol_count
                .checked_mul(24)
                .ok_or(FileParseError::ValueTooLarge)?
        ],
        8,
    )?;
    let version_sections = versions.emit(&mut candidate, &ro)?;
    // One SysV bucket is deliberately simple and valid for this small writer.
    let mut hash = Vec::new();
    push(&mut hash, 1, 4);
    push(&mut hash, symbol_count_u32 as u64, 4);
    push(&mut hash, if symbol_count > 1 { 1 } else { 0 }, 4);
    for index in 0..symbol_count {
        push(
            &mut hash,
            if index > 0 && index + 1 < symbol_count {
                (index + 1) as u64
            } else {
                0
            },
            4,
        );
    }
    let hash_section = generated(&mut candidate, &ro, ".hash", hash, 4)?;
    let relative_count = source
        .fixups
        .iter()
        .filter(|f| f.kind == FixupKind::Absolute64)
        .count();
    let relocation_count = relative_count
        .checked_add(source.imports.len())
        .and_then(|v| v.checked_add(runtime.pointer_count() + source.tls_slots.len()))
        .ok_or(FileParseError::ValueTooLarge)?;
    let rela = generated(
        &mut candidate,
        &ro,
        ".rela.dyn",
        vec![
            0;
            relocation_count
                .checked_mul(24)
                .ok_or(FileParseError::ValueTooLarge)?
        ],
        8,
    )?;
    let tag_count = 11
        + runtime.tag_count()
        + versions.tag_count()
        + needed.len()
        + usize::from(soname.is_some())
        + usize::from(runpath.is_some());
    let dynamic_section = generated(&mut candidate, &rw, ".dynamic", vec![0; tag_count * 16], 8)?;
    candidate.extra_programs.push((2, dynamic_section));
    let (_, layout) = emit::build(&candidate)?;
    let mut symbols = vec![0; 24];
    for (symbol, name) in exports.iter().zip(export_names) {
        push(&mut symbols, name as u64, 4);
        push(
            &mut symbols,
            if symbol.binding == Binding::Weak {
                0x20
            } else {
                0x10
            },
            1,
        );
        push(
            &mut symbols,
            match symbol.visibility {
                Visibility::Default => 0,
                Visibility::Hidden => 2,
                Visibility::Protected => 3,
            },
            1,
        );
        push(&mut symbols, (symbol.section + 1) as u64, 2);
        push(&mut symbols, symbol_address(source, &layout, symbol)?, 8);
        push(&mut symbols, symbol.size, 8);
    }
    for name in import_names {
        push(&mut symbols, name as u64, 4);
        push(&mut symbols, 0x10, 1);
        push(&mut symbols, 0, 1);
        push(&mut symbols, 0, 2);
        push(&mut symbols, 0, 8);
        push(&mut symbols, 0, 8);
    }
    candidate.sections[dynsym].spec.data = symbols;
    let mut relocations = Vec::new();
    for fixup in source
        .fixups
        .iter()
        .filter(|f| f.kind == FixupKind::Absolute64)
    {
        let offset = address(&layout, fixup.section)?
            .checked_add(fixup.offset)
            .ok_or(FileParseError::ValueTooLarge)?;
        let (info, addend) = pointer_relocation(source, &layout, fixup.target, fixup.addend)?;
        push(&mut relocations, offset, 8);
        push(&mut relocations, info, 8);
        push(&mut relocations, addend as u64, 8);
        let segment = source.sections[fixup.section]
            .segment
            .ok_or(FileParseError::InvalidFileFormat)?;
        if !source.segments[segment].write {
            return Err(FileParseError::UnsupportedFeature(
                "runtime relocation into a read-only ELF segment".into(),
            ));
        }
    }
    for (index, (_, _, section)) in source.imports.iter().enumerate() {
        push(&mut relocations, address(&layout, *section)?, 8);
        push(
            &mut relocations,
            (((exports.len() + 1 + index) as u64) << 32) | 6,
            8,
        );
        push(&mut relocations, 0, 8);
    }
    runtime.relocations(&candidate, &layout, &mut relocations)?;
    for (section, offset) in &source.tls_slots {
        push(&mut relocations, address(&layout, *section)?, 8);
        push(&mut relocations, 16, 8); // R_X86_64_DTPMOD64, current module.
        push(&mut relocations, 0, 8);
        candidate.sections[*section].spec.data[8..16].copy_from_slice(&offset.to_le_bytes());
    }
    candidate.sections[rela].spec.data = relocations;
    let mut dynamic = Vec::new();
    for name in needed {
        push(&mut dynamic, 1, 8);
        push(&mut dynamic, name as u64, 8);
    }
    for (tag, value) in [
        (4, address(&layout, hash_section)?),
        (5, address(&layout, dynstr)?),
        (6, address(&layout, dynsym)?),
        (10, strings_len as u64),
        (11, 24),
        (7, address(&layout, rela)?),
        (8, (relocation_count * 24) as u64),
        (9, 24),
        (30, 8),
        (
            0x6ffffffb,
            if source.kind == ImageKind::Pie {
                0x08000001
            } else {
                1
            },
        ),
    ] {
        push(&mut dynamic, tag, 8);
        push(&mut dynamic, value, 8);
    }
    if let Some(name) = soname {
        push(&mut dynamic, 14, 8);
        push(&mut dynamic, name as u64, 8);
    }
    if let Some(path) = runpath {
        push(&mut dynamic, 29, 8);
        push(&mut dynamic, path as u64, 8);
    }
    runtime.tags(&layout, &mut dynamic)?;
    versions.tags(&version_sections, &layout, &mut dynamic)?;
    push(&mut dynamic, 0, 8);
    push(&mut dynamic, 0, 8);
    candidate.sections[dynamic_section].spec.data = dynamic;
    runtime::resolve_unwind(&mut candidate, &layout)?;
    let (mut image, mut final_layout) = emit::build(&candidate)?;
    if source.section_table {
        let table = usize::try_from(image.header.sh_off.value)
            .map_err(|_| FileParseError::ValueTooLarge)?;
        for (index, kind, link, entry_size, info) in [
            (dynstr, 3, 0, 0, 0),
            (dynsym, 11, dynstr + 1, 24, 1),
            (hash_section, 5, dynsym + 1, 4, 0),
            (rela, 4, dynsym + 1, 24, 0),
            (dynamic_section, 6, dynstr + 1, 16, 0),
        ] {
            let offset = table + (index + 1) * 64;
            image.buffer[offset + 4..offset + 8].copy_from_slice(&(kind as u32).to_le_bytes());
            image.buffer[offset + 40..offset + 44].copy_from_slice(&(link as u32).to_le_bytes());
            image.buffer[offset + 44..offset + 48].copy_from_slice(&(info as u32).to_le_bytes());
            image.buffer[offset + 56..offset + 64]
                .copy_from_slice(&(entry_size as u64).to_le_bytes());
        }
        runtime.patch_section_headers(&mut image, table)?;
        versions.patch_sections(&version_sections, dynstr, dynsym, &mut image, table);
        if let Some(tls) = source.tls {
            let off = table + (tls + 1) * 64 + 8;
            let flags = u64::from_le_bytes(
                image.buffer[off..off + 8]
                    .try_into()
                    .map_err(|_| FileParseError::BufferOverflow)?,
            ) | 0x400;
            image.buffer[off..off + 8].copy_from_slice(&flags.to_le_bytes());
        }
        image = ELF::from_buffer(image.buffer)?;
    }
    final_layout.sections.truncate(source.sections.len());
    final_layout.segments.truncate(source.segments.len());
    Ok((image, final_layout))
}
