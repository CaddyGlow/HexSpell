use super::*;
struct Part {
    name: String,
    data: Vec<u8>,
    size: u32,
    flags: u32,
}
fn part(name: &str, data: Vec<u8>, flags: u32) -> Result<Part> {
    Ok(Part {
        name: name.to_string(),
        size: u32n(data.len())?,
        data,
        flags,
    })
}
fn put(b: &mut [u8], o: usize, v: u64, w: usize) -> Result<()> {
    let dst = b
        .get_mut(o..o.checked_add(w).ok_or(FileParseError::ValueTooLarge)?)
        .ok_or(FileParseError::BufferOverflow)?;
    if w < 8 && v >= (1u64 << (w * 8)) {
        return Err(FileParseError::ValueTooLarge);
    }
    dst.copy_from_slice(&v.to_le_bytes()[..w]);
    Ok(())
}
fn reserve(b: &mut Vec<u8>, n: usize) -> Result<usize> {
    let o = b.len();
    let end = o.checked_add(n).ok_or(FileParseError::ValueTooLarge)?;
    u32n(end)?;
    b.resize(end, 0);
    Ok(o)
}
fn text(b: &mut Vec<u8>, s: &str) -> Result<usize> {
    let o = reserve(b, s.len() + 1)?;
    b[o..o + s.len()].copy_from_slice(s.as_bytes());
    Ok(o)
}
fn padded(b: &mut Vec<u8>, a: usize) -> Result<()> {
    let end = align(u32n(b.len())?, a as u32)? as usize;
    b.resize(end, 0);
    Ok(())
}
struct Imports {
    bytes: Vec<u8>,
    slots: Vec<usize>,
    pointers: Vec<usize>,
    iat_start: usize,
    iat_size: usize,
    descriptor_size: usize,
}
fn imports(b: &PeBuilder, w: usize) -> Result<Imports> {
    let mut groups: Vec<(&str, Vec<usize>)> = Vec::new();
    for (i, x) in b.imports.iter().enumerate() {
        if let Some(g) = groups.iter_mut().find(|g| g.0 == x.dll) {
            g.1.push(i)
        } else {
            groups.push((&x.dll, vec![i]))
        }
    }
    let descriptor_size = (groups.len() + 1) * 20;
    let mut bytes = vec![0; descriptor_size];
    padded(&mut bytes, w)?;
    let iat_start = bytes.len();
    let mut slots = vec![0; b.imports.len()];
    let mut iats = Vec::new();
    for (_, g) in &groups {
        let o = reserve(&mut bytes, (g.len() + 1) * w)?;
        iats.push(o);
        for (j, i) in g.iter().enumerate() {
            slots[*i] = o + j * w;
        }
    }
    let iat_size = bytes.len() - iat_start;
    let mut pointers = Vec::new();
    for (gi, (dll, g)) in groups.iter().enumerate() {
        padded(&mut bytes, w)?;
        let ilt = reserve(&mut bytes, (g.len() + 1) * w)?;
        let dn = text(&mut bytes, dll)?;
        for (at, value) in [(gi * 20, ilt), (gi * 20 + 12, dn), (gi * 20 + 16, iats[gi])] {
            put(&mut bytes, at, value as u64, 4)?;
            pointers.push(at)
        }
        for (j, i) in g.iter().enumerate() {
            let value = match &b.imports[*i].name {
                ImportName::Ordinal(n) => (1u64 << (w * 8 - 1)) | u64::from(*n),
                ImportName::Name(n) => {
                    padded(&mut bytes, 2)?;
                    let o = reserve(&mut bytes, 2)?;
                    text(&mut bytes, n)?;
                    pointers.push(ilt + j * w);
                    pointers.push(slots[*i]);
                    o as u64
                }
            };
            put(&mut bytes, ilt + j * w, value, w)?;
            put(&mut bytes, slots[*i], value, w)?;
        }
    }
    Ok(Imports {
        bytes,
        slots,
        pointers,
        iat_start,
        iat_size,
        descriptor_size,
    })
}
fn export_bytes(b: &PeBuilder) -> Result<Vec<u8>> {
    if b.exports.is_empty() {
        return Ok(Vec::new());
    }
    let minimum = b
        .exports
        .iter()
        .map(|e| e.ordinal)
        .min()
        .ok_or(FileParseError::InvalidFileFormat)?;
    let min = b.export_base.unwrap_or(minimum);
    if min > minimum {
        return invalid();
    }
    let max = b
        .exports
        .iter()
        .map(|e| e.ordinal)
        .max()
        .ok_or(FileParseError::InvalidFileFormat)?;
    let count = add(max - min, 1)?;
    if count > 65536 {
        return Err(FileParseError::ValueTooLarge);
    }
    let names = b.exports.iter().filter(|e| e.name.is_some()).count();
    let mut out = vec![0; 40 + count as usize * 4 + names * 6];
    text(&mut out, &b.export_name)?;
    for e in &b.exports {
        if let Some(n) = &e.name {
            text(&mut out, n)?;
        }
    }
    Ok(out)
}
pub(super) fn build(b: &PeBuilder) -> Result<(PE, LayoutReport)> {
    if !b.file_alignment.is_power_of_two()
        || !(512..=65536).contains(&b.file_alignment)
        || !b.section_alignment.is_power_of_two()
        || b.section_alignment < 4096
        || b.section_alignment < b.file_alignment
        || !b.image_base.is_multiple_of(65536)
    {
        return invalid();
    }
    if b.target == Target::X86 && b.image_base > u32::MAX as u64 {
        return Err(FileParseError::ValueTooLarge);
    }
    let w = if b.target == Target::X86 { 4 } else { 8 };
    let opt = if w == 4 { 224 } else { 240 };
    let mut parts: Vec<Part> = b
        .sections
        .iter()
        .map(|s| Part {
            name: s.name.clone(),
            data: s.data.clone(),
            size: s.virtual_size,
            flags: s.characteristics,
        })
        .collect();
    let im = if b.imports.is_empty() {
        None
    } else {
        Some(imports(b, w)?)
    };
    let impidx = if let Some(i) = &im {
        let n = parts.len();
        parts.push(part(".idata", i.bytes.clone(), 0xc0000040)?);
        Some(n)
    } else {
        None
    };
    let ex = export_bytes(b)?;
    let exidx = if ex.is_empty() {
        None
    } else {
        let n = parts.len();
        parts.push(part(".edata", ex, 0x40000040)?);
        Some(n)
    };
    let tlsidx = if let Some(t) = &b.tls {
        let n = parts.len();
        parts.push(part(
            ".tlsdir",
            vec![0; if w == 4 { 24 } else { 40 } + (t.callbacks.len() + 1) * w],
            0x40000040,
        )?);
        Some(n)
    } else {
        None
    };
    let funidx = if b.functions.is_empty() {
        None
    } else {
        let n = parts.len();
        parts.push(part(".pdata", vec![0; b.functions.len() * 12], 0x40000040)?);
        Some(n)
    };
    let residx = if let Some(resources) = &b.resources {
        let n = parts.len();
        parts.push(part(".rsrc", resources.serialize(0)?, 0x40000040)?);
        Some(n)
    } else {
        None
    };
    let reloc_needed = b
        .fixups
        .iter()
        .any(|f| matches!(f.kind, FixupKind::Va32 | FixupKind::Va64))
        || b.tls.is_some();
    let n = parts.len() + usize::from(reloc_needed);
    if n == 0 || n > 96 {
        return invalid();
    }
    let headers = align(u32n(0x80 + 24 + opt + n * 40)?, b.file_alignment)?;
    let mut raw = headers;
    let mut rva = align(headers, b.section_alignment)?;
    let mut layout = Vec::new();
    for p in &parts {
        let rs = if p.data.is_empty() {
            0
        } else {
            align(u32n(p.data.len())?, b.file_alignment)?
        };
        layout.push(ResolvedSection {
            rva,
            file_offset: raw as usize,
            raw_size: rs,
            virtual_size: p.size,
        });
        raw = add(raw, rs)?;
        rva = align(add(rva, p.size.max(rs))?, b.section_alignment)?;
    }
    b.image_base
        .checked_add(rva as u64)
        .ok_or(FileParseError::ValueTooLarge)?;
    if b.kind == ImageKind::Executable && b.entry.is_none() {
        return invalid();
    }
    let mut report = LayoutReport {
        owner: b.owner.clone(),
        sections: layout[..b.sections.len()].to_vec(),
        symbols: Vec::new(),
        imports: Vec::new(),
    };
    for (s, o) in &b.symbols {
        let p = &layout[s.index];
        let sr = add(p.rva, *o)?;
        let va = b
            .image_base
            .checked_add(sr as u64)
            .ok_or(FileParseError::ValueTooLarge)?;
        if w == 4 && va > u32::MAX as u64 {
            return Err(FileParseError::ValueTooLarge);
        }
        report.symbols.push(ResolvedLocation {
            rva: sr,
            va,
            file_offset: if (*o as usize) < b.sections[s.index].data.len() {
                Some(p.file_offset + *o as usize)
            } else {
                None
            },
        })
    }
    let mut dirs = [(0u32, 0u32); 16];
    if let (Some(resources), Some(idx)) = (&b.resources, residx) {
        parts[idx].data = resources.serialize(layout[idx].rva)?;
        dirs[2] = (layout[idx].rva, u32n(parts[idx].data.len())?);
    }
    if let (Some(i), Some(idx)) = (&im, impidx) {
        let base = layout[idx].rva;
        for off in &i.pointers {
            let width = if *off < i.descriptor_size { 4 } else { w };
            let mut v = 0u64;
            for j in 0..width {
                v |= (parts[idx].data[*off + j] as u64) << (j * 8)
            }
            let resolved = v + base as u64;
            // Only thunk pointers carry the ordinal discriminator; descriptor
            // pointers remain ordinary 32-bit RVAs even in high layouts.
            if w == 4 && *off >= i.descriptor_size && resolved & 0x8000_0000 != 0 {
                return Err(FileParseError::ValueTooLarge);
            }
            put(&mut parts[idx].data, *off, resolved, width)?;
        }
        for o in &i.slots {
            let sr = add(base, u32n(*o)?)?;
            report.imports.push(ResolvedLocation {
                rva: sr,
                va: b.image_base + sr as u64,
                file_offset: Some(layout[idx].file_offset + o),
            })
        }
        dirs[1] = (base, u32n(i.descriptor_size)?);
        dirs[12] = (add(base, u32n(i.iat_start)?)?, u32n(i.iat_size)?);
    }
    if let Some(idx) = exidx {
        let base = layout[idx].rva;
        let data = &mut parts[idx].data;
        data.fill(0);
        let minimum = b
            .exports
            .iter()
            .map(|e| e.ordinal)
            .min()
            .ok_or(FileParseError::InvalidFileFormat)?;
        let min = b.export_base.unwrap_or(minimum);
        if min > minimum {
            return invalid();
        }
        let max = b
            .exports
            .iter()
            .map(|e| e.ordinal)
            .max()
            .ok_or(FileParseError::InvalidFileFormat)?;
        let count = (max - min + 1) as usize;
        let mut named: Vec<_> = b.exports.iter().filter(|e| e.name.is_some()).collect();
        named.sort_by(|a, c| a.name.cmp(&c.name));
        let np = 40 + count * 4;
        let no = np + named.len() * 4;
        let mut strings = no + named.len() * 2;
        put(data, 12, add(base, u32n(strings)?)? as u64, 4)?;
        data[strings..strings + b.export_name.len()].copy_from_slice(b.export_name.as_bytes());
        strings += b.export_name.len() + 1;
        for (o, v) in [
            (16, min),
            (20, count as u32),
            (24, named.len() as u32),
            (28, add(base, 40)?),
            (32, add(base, u32n(np)?)?),
            (36, add(base, u32n(no)?)?),
        ] {
            put(data, o, v as u64, 4)?;
        }
        for e in &b.exports {
            put(
                data,
                40 + (e.ordinal - min) as usize * 4,
                report.symbols[e.symbol.index].rva as u64,
                4,
            )?;
        }
        for (j, e) in named.iter().enumerate() {
            let name = e.name.as_deref().ok_or(FileParseError::InvalidFileFormat)?;
            put(data, np + j * 4, add(base, u32n(strings)?)? as u64, 4)?;
            put(data, no + j * 2, (e.ordinal - min) as u64, 2)?;
            data[strings..strings + name.len()].copy_from_slice(name.as_bytes());
            strings += name.len() + 1;
        }
        dirs[0] = (base, u32n(data.len())?);
    }
    let mut reloc: BTreeMap<u32, u16> = BTreeMap::new();
    let mut writes: Vec<(usize, usize, usize)> = Vec::new();
    for f in &b.fixups {
        let idx = f.section.index;
        let sec = parts
            .get_mut(idx)
            .ok_or(FileParseError::InvalidFileFormat)?;
        let width = match f.kind {
            FixupKind::Va64 => 8,
            _ => 4,
        };
        let end = (f.offset as usize)
            .checked_add(width)
            .ok_or(FileParseError::ValueTooLarge)?;
        if end > sec.data.len() {
            return Err(FileParseError::BufferOverflow);
        }
        if writes
            .iter()
            .any(|(s, a, z)| *s == idx && (f.offset as usize) < *z && end > *a)
        {
            return invalid();
        }
        writes.push((idx, f.offset as usize, end));
        let loc = match &f.target {
            FixupTarget::Symbol(s) => &report.symbols[s.index],
            FixupTarget::Import(i) => &report.imports[i.index],
        };
        let value = match f.kind {
            FixupKind::Rva32 => loc.rva as i128,
            FixupKind::Va32 if w == 4 => loc.va as i128,
            FixupKind::Va64 if w == 8 => loc.va as i128,
            FixupKind::Rel32 { origin } => {
                if origin as usize > sec.data.len() {
                    return Err(FileParseError::BufferOverflow);
                }
                loc.rva as i128 - add(layout[idx].rva, origin)? as i128
            }
            _ => return invalid(),
        } + f.addend as i128;
        let v = if matches!(f.kind, FixupKind::Rel32 { .. }) {
            i32::try_from(value).map_err(|_| FileParseError::ValueTooLarge)? as u32 as u64
        } else {
            u64::try_from(value).map_err(|_| FileParseError::ValueTooLarge)?
        };
        put(&mut sec.data, f.offset as usize, v, width)?;
        if matches!(f.kind, FixupKind::Va32 | FixupKind::Va64) {
            reloc.insert(add(layout[idx].rva, f.offset)?, if w == 4 { 3 } else { 10 });
        }
    }
    if let (Some(t), Some(idx)) = (&b.tls, tlsidx) {
        let base = layout[idx].rva;
        if !report.symbols[t.start.index]
            .va
            .is_multiple_of(t.alignment as u64)
        {
            return invalid();
        }
        let ds = if w == 4 { 24 } else { 40 };
        let data = &mut parts[idx].data;
        for (j, s) in [&t.start, &t.end, &t.index].iter().enumerate() {
            put(data, j * w, report.symbols[s.index].va, w)?;
            reloc.insert(add(base, (j * w) as u32)?, if w == 4 { 3 } else { 10 });
        }
        put(data, 3 * w, b.image_base + base as u64 + ds as u64, w)?;
        reloc.insert(add(base, (3 * w) as u32)?, if w == 4 { 3 } else { 10 });
        put(data, 4 * w, t.zero_fill as u64, 4)?;
        put(
            data,
            4 * w + 4,
            ((t.alignment.trailing_zeros() + 1) << 20) as u64,
            4,
        )?;
        for (j, s) in t.callbacks.iter().enumerate() {
            put(data, ds + j * w, report.symbols[s.index].va, w)?;
            reloc.insert(add(base, (ds + j * w) as u32)?, if w == 4 { 3 } else { 10 });
        }
        dirs[9] = (base, ds as u32);
    }
    if let Some(idx) = funidx {
        let mut fs: Vec<_> = b
            .functions
            .iter()
            .map(|(a, z, u)| {
                (
                    report.symbols[a.index].rva,
                    report.symbols[z.index].rva,
                    report.symbols[u.index].rva,
                )
            })
            .collect();
        fs.sort_unstable();
        for pair in fs.windows(2) {
            if pair[0].1 > pair[1].0 {
                return invalid();
            }
        }
        for (j, (a, z, u)) in fs.iter().enumerate() {
            for (k, v) in [a, z, u].iter().enumerate() {
                put(&mut parts[idx].data, j * 12 + k * 4, **v as u64, 4)?;
            }
        }
        dirs[3] = (layout[idx].rva, u32n(parts[idx].data.len())?);
    }
    if reloc_needed {
        let mut data = Vec::new();
        let mut groups: BTreeMap<u32, Vec<u16>> = BTreeMap::new();
        for (addr, kind) in reloc {
            groups
                .entry(addr & !4095)
                .or_default()
                .push((kind << 12) | (addr as u16 & 4095));
        }
        for (page, mut entries) in groups {
            if entries.len() % 2 != 0 {
                entries.push(0)
            }
            let o = reserve(&mut data, 8 + entries.len() * 2)?;
            put(&mut data, o, page as u64, 4)?;
            put(&mut data, o + 4, (8 + entries.len() * 2) as u64, 4)?;
            for (j, e) in entries.iter().enumerate() {
                put(&mut data, o + 8 + j * 2, *e as u64, 2)?;
            }
        }
        let size = u32n(data.len())?;
        let rs = align(size, b.file_alignment)?;
        dirs[5] = (rva, size);
        layout.push(ResolvedSection {
            rva,
            file_offset: raw as usize,
            raw_size: rs,
            virtual_size: size,
        });
        raw = add(raw, rs)?;
        rva = align(add(rva, size.max(rs))?, b.section_alignment)?;
        parts.push(part(".reloc", data, 0x42000040)?);
    }
    if w == 4
        && b.image_base
            .checked_add(rva as u64)
            .is_none_or(|v| v > u32::MAX as u64)
    {
        return Err(FileParseError::ValueTooLarge);
    }
    b.image_base
        .checked_add(rva as u64)
        .ok_or(FileParseError::ValueTooLarge)?;
    let mut out = vec![0; raw as usize];
    put(&mut out, 0, 0x5a4d, 2)?;
    put(&mut out, 0x3c, 0x80, 4)?;
    put(&mut out, 0x80, 0x4550, 4)?;
    put(&mut out, 0x84, if w == 4 { 0x14c } else { 0x8664 }, 2)?;
    put(&mut out, 0x86, n as u64, 2)?;
    put(&mut out, 0x94, opt as u64, 2)?;
    put(
        &mut out,
        0x96,
        0x2 | if w == 4 { 0x100 } else { 0x20 }
            | if b.kind == ImageKind::Dll { 0x2000 } else { 0 }
            | if reloc_needed { 0 } else { 1 },
        2,
    )?;
    let o = 0x98;
    put(&mut out, o, if w == 4 { 0x10b } else { 0x20b }, 2)?;
    let mut code = 0u32;
    let mut init = 0u32;
    let mut uninit = 0u32;
    let mut basecode = 0;
    let mut basedata = 0;
    for (p, l) in parts.iter().zip(&layout) {
        if p.flags & 0x20 != 0 {
            code = add(code, l.raw_size)?;
            if basecode == 0 {
                basecode = l.rva
            }
        }
        if p.flags & 0x40 != 0 {
            init = add(init, l.raw_size)?;
            if basedata == 0 {
                basedata = l.rva;
            }
        }
        if p.flags & 0x80 != 0 {
            uninit = add(uninit, p.size)?;
            if basedata == 0 {
                basedata = l.rva;
            }
        }
    }
    for (at, v) in [
        (4, code),
        (8, init),
        (12, uninit),
        (
            16,
            b.entry.as_ref().map_or(0, |s| report.symbols[s.index].rva),
        ),
        (20, basecode),
        (32, b.section_alignment),
        (36, b.file_alignment),
        (56, rva),
        (60, headers),
    ] {
        put(&mut out, o + at, v as u64, 4)?;
    }
    if w == 4 {
        put(&mut out, o + 24, basedata as u64, 4)?;
        put(&mut out, o + 28, b.image_base, 4)?;
    } else {
        put(&mut out, o + 24, b.image_base, 8)?;
    }
    put(&mut out, o + 40, 6, 2)?;
    put(&mut out, o + 48, 6, 2)?;
    put(&mut out, o + 68, b.subsystem as u64, 2)?;
    put(
        &mut out,
        o + 70,
        0x100 | if reloc_needed { 0x40 } else { 0 },
        2,
    )?;
    for (j, v) in [0x100000, 0x1000, 0x100000, 0x1000].iter().enumerate() {
        put(&mut out, o + 72 + j * w, *v, w)?;
    }
    let dc = if w == 4 { 92 } else { 108 };
    put(&mut out, o + dc, 16, 4)?;
    for (j, (a, s)) in dirs.iter().enumerate() {
        put(&mut out, o + dc + 4 + j * 8, *a as u64, 4)?;
        put(&mut out, o + dc + 8 + j * 8, *s as u64, 4)?;
    }
    for (j, (p, l)) in parts.iter().zip(&layout).enumerate() {
        let sh = o + opt + j * 40;
        out[sh..sh + p.name.len()].copy_from_slice(p.name.as_bytes());
        for (at, v) in [
            (8, p.size),
            (12, l.rva),
            (16, l.raw_size),
            (
                20,
                if l.raw_size == 0 {
                    0
                } else {
                    l.file_offset as u32
                },
            ),
            (36, p.flags),
        ] {
            put(&mut out, sh + at, v as u64, 4)?;
        }
        out[l.file_offset..l.file_offset + p.data.len()].copy_from_slice(&p.data);
    }
    let mut pe = PE::from_buffer(out)?;
    let checksum = pe.calc_checksum();
    pe.optional_header
        .checksum
        .update(&mut pe.buffer, checksum)?;
    Ok((pe, report))
}
