//! Linux AMD64 runtime metadata. ABI: System V AMD64 psABI 1.0, sections 3.6,
//! 4.2.4 and 10.3; DWARF 4 section 6.4 and LSB Core AMD64 .eh_frame_hdr.
//! TLS: Ulrich Drepper, ELF Handling For Thread-Local Storage, v0.21 (2013),
//! sections 2 and 4.6: https://www.akkadia.org/drepper/tls.pdf
//! Unwind pointer encodings: LSB Core 5.0 section 10.5.1:
//! https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html
use super::*;

#[derive(Clone)]
pub(super) struct Unwind {
    frame: usize,
    header: usize,
    fdes: Vec<(usize, usize)>,
}
impl ElfBuilder {
    /// Appends a loader initializer. Constructors run in registration order.
    /// Supported for shared objects; PIE requires a caller-provided CRT lifecycle
    /// and is rejected when these arrays are requested. The function must be initialized executable code.
    pub fn add_initializer(&mut self, function: &SymbolId) -> Result<()> {
        let index = self.runtime_function(function)?;
        self.initializers.push(index);
        Ok(())
    }
    /// Appends a loader finalizer. Destructors run in reverse registration order.
    pub fn add_finalizer(&mut self, function: &SymbolId) -> Result<()> {
        let index = self.runtime_function(function)?;
        self.finalizers.push(index);
        Ok(())
    }
    fn runtime_function(&self, function: &SymbolId) -> Result<usize> {
        let index = self.check(&function.owner, function.index, self.symbols.len())?;
        let symbol = &self.symbols[index];
        let section = &self.sections[symbol.section];
        if symbol.offset >= section.spec.data.len() as u64
            || !section.segment.is_some_and(|s| self.segments[s].execute)
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        Ok(index)
    }
    /// Adds the image's TLS initialization template and its PT_TLS header.
    ///
    /// Linux AMD64 general-dynamic TLS is supported. Zero bytes in the supplied
    /// template initialize independent per-thread storage. Access uses a descriptor
    /// from `add_tls_address_slot` and the loader's `__tls_get_addr` function.
    /// The template is not ordinary shared writable data; do not address it as such.
    pub fn add_tls_template(&mut self, bytes: Vec<u8>, alignment: u64) -> Result<SectionId> {
        if self.tls.is_some()
            || bytes.is_empty()
            || !alignment.is_power_of_two()
            || alignment > 4096
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        let segment = self.add_segment(SegmentSpec::RW)?;
        let mut spec = SectionSpec::new(".tdata", bytes);
        spec.alignment = alignment;
        let section = self.add_section(Some(&segment), spec)?;
        self.tls = Some(section.index);
        Ok(section)
    }
    /// Adds a Linux AMD64 general-dynamic `tls_index` descriptor.
    ///
    /// Pass its address in RDI to `__tls_get_addr` (normally imported from
    /// `ld-linux-x86-64.so.2`); RAX receives the current thread's template+offset.
    /// The dynamic loader fills the module ID with `R_X86_64_DTPMOD64`.
    pub fn add_tls_address_slot(&mut self, template: &SectionId, offset: u64) -> Result<SymbolId> {
        let section = self.check(&template.owner, template.index, self.sections.len())?;
        if self.tls != Some(section) || offset >= self.sections[section].spec.data.len() as u64 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let name = alloc::format!("__hexspell_tls_{}", self.tls_slots.len());
        if self.symbols.iter().any(|s| s.name == name) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let segment = self.add_segment(SegmentSpec::RW)?;
        let mut spec = SectionSpec::new(".got.tls", vec![0; 16]);
        spec.alignment = 8;
        let slot = self.add_section(Some(&segment), spec)?;
        let symbol = self.define_symbol(&name, &slot, 0, 16, Binding::Local)?;
        self.tls_slots.push((slot.index, offset));
        Ok(symbol)
    }
    /// Installs caller-provided DWARF32 `.eh_frame` records and builds the loader's
    /// binary-search index (`PT_GNU_EH_FRAME`).
    ///
    /// This scoped profile accepts a single version-1 CIE with `zR` augmentation,
    /// code alignment 1, data alignment -8, AMD64 return register 16 and
    /// `DW_EH_PE_pcrel | DW_EH_PE_sdata4` FDE pointers. Each `(record_offset,
    /// function)` identifies an FDE; its zero initial-location field is patched to
    /// the function. The caller supplies valid CFI instructions and a nonzero
    /// four-byte function range. Personality functions, LSDA and exception handlers
    /// are outside this profile. Record structure and pointer encodings are checked;
    /// CFI instruction semantics remain the caller's responsibility.
    pub fn add_eh_frame(&mut self, bytes: Vec<u8>, fdes: &[(u32, SymbolId)]) -> Result<SectionId> {
        if self.unwind.is_some() || fdes.is_empty() {
            return Err(FileParseError::InvalidFileFormat);
        }
        let mut entries = Vec::new();
        for (offset, function) in fdes {
            let symbol = self.runtime_function(function)?;
            entries.push((*offset as usize, symbol));
        }
        validate_frame(&bytes, &entries)?;
        let header_length = entries
            .len()
            .checked_mul(8)
            .and_then(|value| value.checked_add(12))
            .ok_or(FileParseError::ValueTooLarge)?;
        let segment = self.add_segment(SegmentSpec::R)?;
        let mut spec = SectionSpec::new(".eh_frame", bytes);
        spec.alignment = 8;
        let frame = self.add_section(Some(&segment), spec)?;
        let mut spec = SectionSpec::new(".eh_frame_hdr", vec![0; header_length]);
        spec.alignment = 4;
        let header = self.add_section(Some(&segment), spec)?;
        self.unwind = Some(Unwind {
            frame: frame.index,
            header: header.index,
            fdes: entries,
        });
        Ok(frame)
    }
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or(FileParseError::BufferOverflow)?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(FileParseError::BufferOverflow)?
            .try_into()
            .map_err(|_| FileParseError::BufferOverflow)?,
    ))
}
fn validate_frame(bytes: &[u8], entries: &[(usize, usize)]) -> Result<()> {
    let cie_len = u32_at(bytes, 0)? as usize;
    // Canonical CIE profile; bytes after the augmentation are caller-supplied CFI.
    if cie_len < 13
        || bytes.get(4..17) != Some(&[0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b])
    {
        return Err(FileParseError::UnsupportedFeature(
            "ELF unwind CIE profile".into(),
        ));
    }
    let mut cursor = cie_len
        .checked_add(4)
        .ok_or(FileParseError::ValueTooLarge)?;
    let mut seen = Vec::new();
    while cursor < bytes.len() {
        let length = u32_at(bytes, cursor)? as usize;
        if length == 0 {
            if cursor + 4 != bytes.len() {
                return Err(FileParseError::InvalidFileFormat);
            }
            cursor += 4;
            break;
        }
        if length == u32::MAX as usize || length < 13 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let end = cursor
            .checked_add(4)
            .and_then(|v| v.checked_add(length))
            .ok_or(FileParseError::ValueTooLarge)?;
        if end > bytes.len()
            || u32_at(bytes, cursor + 4)? as usize != cursor + 4
            || u32_at(bytes, cursor + 8)? != 0
            || u32_at(bytes, cursor + 12)? == 0
            || bytes[cursor + 16] != 0
            || !entries.iter().any(|(off, _)| *off == cursor)
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        seen.push(cursor);
        cursor = end;
    }
    if cursor != bytes.len()
        || seen.len() != entries.len()
        || entries
            .iter()
            .any(|(off, _)| seen.iter().filter(|s| *s == off).count() != 1)
        || entries
            .iter()
            .enumerate()
            .any(|(i, a)| entries[..i].iter().any(|b| a.0 == b.0))
    {
        return Err(FileParseError::InvalidFileFormat);
    }
    Ok(())
}
pub(super) struct Prepared {
    arrays: Vec<(usize, u64, Vec<usize>)>,
}
impl Prepared {
    pub(super) fn pointer_count(&self) -> usize {
        self.arrays.iter().map(|a| a.2.len()).sum()
    }
    pub(super) fn tag_count(&self) -> usize {
        self.arrays.len() * 2
    }
    pub(super) fn relocations(
        &self,
        builder: &ElfBuilder,
        layout: &LayoutReport,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        for (section, _, symbols) in &self.arrays {
            for (index, symbol) in symbols.iter().enumerate() {
                let (info, addend) = dynamic::pointer_relocation(builder, layout, *symbol, 0)?;
                let address = layout.sections[*section]
                    .virtual_address
                    .ok_or(FileParseError::InvalidFileFormat)?
                    + index as u64 * 8;
                for value in [address, info, addend as u64] {
                    out.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
        Ok(())
    }
    pub(super) fn tags(&self, layout: &LayoutReport, out: &mut Vec<u8>) -> Result<()> {
        for (section, tag, symbols) in &self.arrays {
            for value in [
                *tag,
                layout.sections[*section]
                    .virtual_address
                    .ok_or(FileParseError::InvalidFileFormat)?,
                *tag + 2,
                symbols.len() as u64 * 8,
            ] {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
        Ok(())
    }
    pub(super) fn patch_section_headers(&self, image: &mut ELF, table: usize) -> Result<()> {
        for (section, tag, _) in &self.arrays {
            let offset = table + (section + 1) * 64;
            let kind: u32 = if *tag == 25 { 14 } else { 15 };
            image.buffer[offset + 4..offset + 8].copy_from_slice(&kind.to_le_bytes());
            image.buffer[offset + 56..offset + 64].copy_from_slice(&8u64.to_le_bytes());
        }
        Ok(())
    }
}
pub(super) fn prepare(builder: &mut ElfBuilder) -> Result<Prepared> {
    let mut arrays = Vec::new();
    for (name, tag, symbols) in [
        (".init_array", 25, builder.initializers.clone()),
        (".fini_array", 26, builder.finalizers.clone()),
    ] {
        if !symbols.is_empty() {
            let segment = builder.add_segment(SegmentSpec::RW)?;
            let mut spec = SectionSpec::new(name, vec![0; symbols.len() * 8]);
            spec.alignment = 8;
            let section = builder.add_section(Some(&segment), spec)?;
            arrays.push((section.index, tag, symbols));
        }
    }
    if let Some(tls) = builder.tls {
        builder.extra_programs.push((7, tls));
    }
    if let Some(unwind) = &builder.unwind {
        builder.extra_programs.push((0x6474e550, unwind.header));
    }
    Ok(Prepared { arrays })
}
fn i32_bytes(value: i128) -> Result<[u8; 4]> {
    Ok(i32::try_from(value)
        .map_err(|_| FileParseError::ValueTooLarge)?
        .to_le_bytes())
}
pub(super) fn resolve_unwind(builder: &mut ElfBuilder, layout: &LayoutReport) -> Result<()> {
    let Some(unwind) = builder.unwind.clone() else {
        return Ok(());
    };
    let frame_address = layout.sections[unwind.frame]
        .virtual_address
        .ok_or(FileParseError::InvalidFileFormat)?;
    let header_address = layout.sections[unwind.header]
        .virtual_address
        .ok_or(FileParseError::InvalidFileFormat)?;
    let mut pairs = Vec::new();
    for (offset, index) in &unwind.fdes {
        let symbol = &builder.symbols[*index];
        let target = layout.sections[symbol.section]
            .virtual_address
            .ok_or(FileParseError::InvalidFileFormat)?
            .checked_add(symbol.offset)
            .ok_or(FileParseError::ValueTooLarge)?;
        let range = u32_at(&builder.sections[unwind.frame].spec.data, offset + 12)? as u64;
        if symbol
            .offset
            .checked_add(range)
            .is_none_or(|end| end > builder.sections[symbol.section].spec.data.len() as u64)
        {
            return Err(FileParseError::BufferOverflow);
        }
        let pointer =
            i32_bytes(i128::from(target) - i128::from(frame_address) - (*offset + 8) as i128)?;
        builder.sections[unwind.frame].spec.data[*offset + 8..*offset + 12]
            .copy_from_slice(&pointer);
        pairs.push((target, frame_address + *offset as u64));
    }
    pairs.sort_unstable();
    if pairs.windows(2).any(|p| p[0].0 == p[1].0) {
        return Err(FileParseError::InvalidFileFormat);
    }
    let bytes = &mut builder.sections[unwind.header].spec.data;
    bytes[..4].copy_from_slice(&[1, 0x1b, 3, 0x3b]);
    bytes[4..8].copy_from_slice(&i32_bytes(
        i128::from(frame_address) - i128::from(header_address) - 4,
    )?);
    bytes[8..12].copy_from_slice(&(pairs.len() as u32).to_le_bytes());
    for (index, (function, fde)) in pairs.iter().enumerate() {
        let offset = 12 + index * 8;
        bytes[offset..offset + 4].copy_from_slice(&i32_bytes(
            i128::from(*function) - i128::from(header_address),
        )?);
        bytes[offset + 4..offset + 8]
            .copy_from_slice(&i32_bytes(i128::from(*fde) - i128::from(header_address))?);
    }
    Ok(())
}
