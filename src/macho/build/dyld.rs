use super::*;
fn string_command_size(s: &str, header: u64) -> Result<u64> {
    align(add(header + 1, s.len() as u64)?, 8)
}
fn valid_string(s: &str) -> Result<()> {
    if s.is_empty() || s.as_bytes().contains(&0) {
        Err(FileParseError::InvalidFileFormat)
    } else {
        Ok(())
    }
}
fn uleb(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let byte = (n & 127) as u8;
        n >>= 7;
        out.push(byte | if n != 0 { 128 } else { 0 });
        if n == 0 {
            break;
        }
    }
}
impl MachOBuilder {
    /// Enables the macOS 13+ dyld profile with modern chained pointer fixups.
    /// Output requires external signing before use on platforms enforcing signatures.
    pub fn enable_dyld(&mut self) -> Result<()> {
        if self.deployment.major < 13 {
            return Err(FileParseError::UnsupportedFeature(
                "dyld profile requires macOS 13".to_string(),
            ));
        }
        self.dyld = true;
        self.revision += 1;
        Ok(())
    }
    /// Adds a dependency; insertion order defines stable one-based dylib ordinals.
    pub fn add_dependency(&mut self, install_name: &str) -> Result<DependencyId> {
        valid_string(install_name)?;
        if self.dependencies.len() >= 127 {
            return Err(FileParseError::ValueTooLarge);
        }
        let index = self.dependencies.len();
        self.dependencies.push(install_name.to_string());
        self.revision += 1;
        Ok(DependencyId {
            owner: self.owner.clone(),
            index,
        })
    }
    /// Adds a dyld runtime search path.
    pub fn add_rpath(&mut self, path: &str) -> Result<()> {
        valid_string(path)?;
        self.rpaths.push(path.to_string());
        self.revision += 1;
        Ok(())
    }
    /// Binds an aligned initialized eight-byte slot to a dependency symbol.
    pub fn add_import(
        &mut self,
        name: &str,
        dependency: &DependencyId,
        section: &SectionId,
        offset: u64,
    ) -> Result<()> {
        valid_string(name)?;
        self.check(&dependency.owner, dependency.index, self.dependencies.len())?;
        self.check(&section.owner, section.index, self.sections.len())?;
        if offset & 7 != 0
            || add(offset, 8)? > self.sections[section.index].spec.data.len() as u64
            || self.segments[self.sections[section.index].segment].protection & 2 == 0
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        if self
            .imports
            .iter()
            .any(|(_, _, s, o)| *s == section.index && *o < offset + 8 && offset < *o + 8)
            || self.fixups.iter().any(|f| {
                f.section == section.index
                    && f.offset < offset + 8
                    && offset
                        < f.offset
                            + if matches!(f.kind, FixupKind::Va64) {
                                8
                            } else {
                                4
                            }
            })
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        self.imports
            .push((name.to_string(), dependency.index, section.index, offset));
        self.revision += 1;
        Ok(())
    }
    pub(super) fn validate_dyld(&self) -> Result<()> {
        if !self.dyld {
            if !self.imports.is_empty() || !self.dependencies.is_empty() || !self.rpaths.is_empty()
            {
                return Err(FileParseError::InvalidFileFormat);
            }
            return Ok(());
        }
        if self.segments[0].name != "__TEXT"
            || self.segments[0].protection != 5
            || (self.install_name.is_none() && self.entry.is_none())
            || self.symbols.len() > 255
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        for f in &self.fixups {
            if matches!(f.kind, FixupKind::Va64)
                && (f.offset & 7 != 0
                    || self.segments[self.sections[f.section].segment].protection & 2 == 0)
            {
                return Err(FileParseError::InvalidFileFormat);
            }
        }
        Ok(())
    }
    pub(super) fn dyld_command_count(&self) -> u64 {
        if self.dyld {
            5 + u64::from(self.install_name.is_none())
                + self.dependencies.len() as u64
                + self.rpaths.len() as u64
        } else {
            0
        }
    }
    pub(super) fn dyld_command_size(&self) -> Result<u64> {
        if !self.dyld {
            return Ok(0);
        }
        let mut n = 24 + 16 + 16 + 80 + 32 + if self.install_name.is_none() { 72 } else { 0 };
        for d in &self.dependencies {
            n = add(n, string_command_size(d, 24)?)?;
        }
        for r in &self.rpaths {
            n = add(n, string_command_size(r, 12)?)?;
        }
        Ok(n)
    }
    pub(super) fn emit_dyld_commands(
        &self,
        b: &mut [u8],
        c: &mut usize,
        chain: u64,
        chain_size: usize,
        exports: u64,
        exports_size: usize,
    ) -> Result<()> {
        if !self.dyld {
            return Ok(());
        }
        if self.install_name.is_none() {
            w32(b, *c, 0x19);
            w32(b, *c + 4, 72);
            wn(b, *c + 8, "__PAGEZERO");
            w64(b, *c + 32, 0x1_0000_0000);
            *c += 72;
        }
        w32(b, *c, 0x1b);
        w32(b, *c + 4, 24);
        *c += 24;
        w32(b, *c, 0xe);
        w32(b, *c + 4, 32);
        w32(b, *c + 8, 12);
        wn(b, *c + 12, "/usr/lib/dyld");
        *c += 32;
        for (cmd, off, size) in [
            (0x80000034, chain, chain_size),
            (0x80000033, exports, exports_size),
        ] {
            w32(b, *c, cmd);
            w32(b, *c + 4, 16);
            w32(b, *c + 8, u32v(off)?);
            w32(b, *c + 12, u32v(size as u64)?);
            *c += 16;
        }
        w32(b, *c, 0xb);
        w32(b, *c + 4, 80);
        w32(b, *c + 20, self.symbols.len() as u32);
        w32(b, *c + 24, self.symbols.len() as u32);
        *c += 80;
        for (cmd, strings, header) in [
            (0xc, &self.dependencies, 24u64),
            (0x8000001c, &self.rpaths, 12u64),
        ] {
            for s in strings {
                let len = string_command_size(s, header)?;
                w32(b, *c, cmd);
                w32(b, *c + 4, u32v(len)?);
                w32(b, *c + 8, header as u32);
                if header == 24 {
                    w32(b, *c + 16, 0x10000);
                    w32(b, *c + 20, 0x10000);
                }
                wn(b, *c + header as usize, s);
                *c += len as usize;
            }
        }
        Ok(())
    }
    fn pointers(&self, sections: &[SectionLayout]) -> Result<Vec<(usize, u64, u64)>> {
        let mut pointers = Vec::new();
        for (i, (_, _, s, o)) in self.imports.iter().enumerate() {
            pointers.push((
                self.sections[*s].segment,
                add(sections[*s].virtual_address, *o)?,
                (1u64 << 63) | i as u64,
            ));
        }
        for f in &self.fixups {
            if matches!(f.kind, FixupKind::Va64) {
                let sym = &self.symbols[f.symbol];
                let target = i128::from(add(sections[sym.section].virtual_address, sym.offset)?)
                    + i128::from(f.addend)
                    - 0x1_0000_0000i128;
                let target = u64::try_from(target).map_err(|_| FileParseError::ValueTooLarge)?;
                if target >= 1 << 36 {
                    return Err(FileParseError::ValueTooLarge);
                }
                pointers.push((
                    self.sections[f.section].segment,
                    add(sections[f.section].virtual_address, f.offset)?,
                    target,
                ));
            }
        }
        pointers.sort_by_key(|p| (p.0, p.1));
        for pair in pointers.windows(2) {
            if pair[0].0 == pair[1].0 && pair[0].1 + 8 > pair[1].1 {
                return Err(FileParseError::InvalidFileFormat);
            }
        }
        Ok(pointers)
    }
    pub(super) fn dyld_blobs(
        &self,
        sections: &[SectionLayout],
        segments: &[SegmentLayout],
        page: u64,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if !self.dyld {
            return Ok((Vec::new(), Vec::new()));
        }
        let pointers = self.pointers(sections)?;
        let extra = usize::from(self.install_name.is_none());
        let count = segments.len() + extra + 1;
        let mut b = vec![0; 28 + 4 + count * 4];
        w32(&mut b, 4, 28);
        w32(&mut b, 28, count as u32);
        for (i, segment) in segments.iter().enumerate() {
            if !pointers.iter().any(|p| p.0 == i) {
                continue;
            }
            let pages = segment.virtual_size / page;
            let pages = u16::try_from(pages).map_err(|_| FileParseError::ValueTooLarge)?;
            let off = b.len();
            let size = 22 + usize::from(pages) * 2;
            b.resize(off + size, 0);
            w32(&mut b, 32 + (i + extra) * 4, (off - 28) as u32);
            w32(&mut b, off, size as u32);
            b[off + 4..off + 6].copy_from_slice(&(page as u16).to_le_bytes());
            b[off + 6..off + 8].copy_from_slice(&6u16.to_le_bytes());
            w64(&mut b, off + 8, segment.virtual_address - 0x1_0000_0000);
            b[off + 20..off + 22].copy_from_slice(&pages.to_le_bytes());
            for p in 0..u64::from(pages) {
                let start = pointers
                    .iter()
                    .find(|x| x.0 == i && (x.1 - segment.virtual_address) / page == p)
                    .map(|x| ((x.1 - segment.virtual_address) % page) as u16)
                    .unwrap_or(0xffff);
                b[off + 22 + p as usize * 2..off + 24 + p as usize * 2]
                    .copy_from_slice(&start.to_le_bytes());
            }
        }
        let imports = b.len();
        let mut strings = vec![0];
        for (name, dep, _, _) in &self.imports {
            let nameoff = u32v(strings.len() as u64)?;
            if nameoff >= 1 << 23 {
                return Err(FileParseError::ValueTooLarge);
            }
            b.extend_from_slice(&(((*dep as u32) + 1) | (nameoff << 9)).to_le_bytes());
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let symboloff = b.len();
        b.extend_from_slice(&strings);
        w32(&mut b, 8, u32v(imports as u64)?);
        w32(&mut b, 12, u32v(symboloff as u64)?);
        w32(&mut b, 16, u32v(self.imports.len() as u64)?);
        w32(&mut b, 20, 1);
        // Unique first-byte edges are required by dyld's radix-tree lookup.
        struct Node {
            terminal: Vec<u8>,
            children: Vec<(u8, usize)>,
        }
        let mut nodes = vec![Node {
            terminal: Vec::new(),
            children: Vec::new(),
        }];
        for symbol in &self.symbols {
            if !symbol.name.is_ascii() {
                return Err(FileParseError::UnsupportedFeature(
                    "non-ASCII dyld export".to_string(),
                ));
            }
            let mut node = 0;
            for byte in symbol.name.bytes() {
                let next = nodes[node]
                    .children
                    .iter()
                    .find(|(b, _)| *b == byte)
                    .map(|(_, n)| *n);
                node = if let Some(next) = next {
                    next
                } else {
                    let next = nodes.len();
                    nodes.push(Node {
                        terminal: Vec::new(),
                        children: Vec::new(),
                    });
                    nodes[node].children.push((byte, next));
                    next
                };
            }
            nodes[node].terminal.push(0);
            uleb(
                &mut nodes[node].terminal,
                add(sections[symbol.section].virtual_address, symbol.offset)? - 0x1_0000_0000,
            );
        }
        let mut offsets = Vec::new();
        let mut length = 0usize;
        for node in &nodes {
            offsets.push(length);
            length = length
                .checked_add(2 + node.terminal.len() + node.children.len() * 7)
                .ok_or(FileParseError::ValueTooLarge)?;
        }
        let mut e = Vec::with_capacity(length);
        for node in &nodes {
            e.push(node.terminal.len() as u8);
            e.extend_from_slice(&node.terminal);
            e.push(node.children.len() as u8);
            for (byte, child) in &node.children {
                e.extend([*byte, 0]);
                let mut offset = offsets[*child];
                for n in 0..5 {
                    e.push((offset & 127) as u8 | if n < 4 { 128 } else { 0 });
                    offset >>= 7;
                }
            }
        }
        Ok((b, e))
    }
    pub(super) fn emit_chained_pointers(
        &self,
        b: &mut [u8],
        sections: &[SectionLayout],
        segments: &[SegmentLayout],
        page: u64,
        _blob: &mut [u8],
    ) -> Result<()> {
        let pointers = self.pointers(sections)?;
        for (i, (segment, address, value)) in pointers.iter().enumerate() {
            let layout = &segments[*segment];
            let next = match pointers.get(i + 1) {
                Some((s, a, _))
                    if s == segment
                        && (a - layout.virtual_address) / page
                            == (address - layout.virtual_address) / page =>
                {
                    (a - address) / 4
                }
                _ => 0,
            };
            if next > 4095 || address & 7 != 0 {
                return Err(FileParseError::ValueTooLarge);
            }
            w64(
                b,
                add(layout.file_offset, address - layout.virtual_address)? as usize,
                *value | (next << 51),
            );
        }
        Ok(())
    }
}

impl MachOBuilder {
    /// Adds ordered constructor pointers, rebased by dyld before invocation.
    pub fn add_initializers(
        &mut self,
        segment: &SegmentId,
        functions: &[SymbolId],
    ) -> Result<SectionId> {
        self.add_function_array(segment, "__mod_init_func", 9, functions)
    }
    /// Adds terminators through generated initializers calling libSystem `__cxa_atexit`.
    /// Requires an explicit libSystem dependency. Callbacks run in reverse registration order.
    /// dyld pins TLV images, so their terminators run at process exit rather than dlclose.
    pub fn add_terminators(
        &mut self,
        segment: &SegmentId,
        functions: &[SymbolId],
    ) -> Result<SectionId> {
        self.check(&segment.owner, segment.index, self.segments.len())?;
        if !self.dyld
            || self.segments[segment.index].protection & 2 == 0
            || self
                .sections
                .iter()
                .any(|s| s.spec.name == "__fini_register")
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        if functions.len() > 255usize.saturating_sub(self.symbols.len() + 1)
            || functions.len() > 255usize.saturating_sub(self.sections.len() + 2)
            || self.symbols.iter().any(|s| {
                s.name == "_hexspell_cxa_atexit" || s.name.starts_with("_hexspell_register_fini_")
            })
        {
            return Err(FileParseError::ValueTooLarge);
        }
        let dependency = self
            .dependencies
            .iter()
            .position(|d| d.ends_with("/libSystem.B.dylib"))
            .ok_or(FileParseError::InvalidFileFormat)?;
        for f in functions {
            self.check(&f.owner, f.index, self.symbols.len())?;
            let sym = &self.symbols[f.index];
            if self.segments[self.sections[sym.section].segment].protection & 4 == 0
                || sym.offset >= self.sections[sym.section].spec.data.len() as u64
            {
                return Err(FileParseError::InvalidFileFormat);
            }
        }
        let mut slot = SectionSpec::new("__fini_register", vec![0; 8]);
        slot.alignment = 3;
        let slot = self.add_section(segment, slot)?;
        self.add_import(
            "___cxa_atexit",
            &DependencyId {
                owner: self.owner.clone(),
                index: dependency,
            },
            &slot,
            0,
        )?;
        let slot = self.add_symbol("_hexspell_cxa_atexit", &slot, 0)?;
        let text = SegmentId {
            owner: self.owner.clone(),
            index: 0,
        };
        let mut registers = Vec::new();
        for (i, function) in functions.iter().enumerate() {
            let bytes = match self.target {
                Target::X86_64 => vec![
                    0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0x31, 0xf6, 0x48, 0x89,
                    0xfa, 0xff, 0x15, 0, 0, 0, 0, 0x5d, 0xc3,
                ],
                Target::Arm64 => [
                    0xa9bf7bfdu32,
                    0x910003fd,
                    0x90000000,
                    0x91000000,
                    0xd2800001,
                    0xaa0003e2,
                    0x90000008,
                    0x91000108,
                    0xf9400108,
                    0xd63f0100,
                    0xa8c17bfd,
                    0xd65f03c0,
                ]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
            };
            let mut spec = SectionSpec::new("__fini_code", bytes);
            spec.alignment = 2;
            let code = self.add_section(&text, spec)?;
            match self.target {
                Target::X86_64 => {
                    self.add_fixup(&code, 7, function, 0, FixupKind::Rel32 { origin: 11 })?;
                    self.add_fixup(&code, 18, &slot, 0, FixupKind::Rel32 { origin: 22 })?;
                }
                Target::Arm64 => {
                    self.add_fixup(&code, 8, function, 0, FixupKind::Arm64Page21)?;
                    self.add_fixup(&code, 12, function, 0, FixupKind::Arm64PageOffset12)?;
                    self.add_fixup(&code, 24, &slot, 0, FixupKind::Arm64Page21)?;
                    self.add_fixup(&code, 28, &slot, 0, FixupKind::Arm64PageOffset12)?;
                }
            }
            registers.push(self.add_symbol(
                &alloc::format!("_hexspell_register_fini_{i}"),
                &code,
                0,
            )?);
        }
        self.add_function_array(segment, "__fini_init", 9, &registers)
    }
    fn add_function_array(
        &mut self,
        segment: &SegmentId,
        name: &str,
        flags: u32,
        functions: &[SymbolId],
    ) -> Result<SectionId> {
        self.check(&segment.owner, segment.index, self.segments.len())?;
        if !self.dyld || self.segments[segment.index].protection & 2 == 0 {
            return Err(FileParseError::InvalidFileFormat);
        }
        for f in functions {
            self.check(&f.owner, f.index, self.symbols.len())?;
            let s = &self.symbols[f.index];
            if self.segments[self.sections[s.section].segment].protection & 4 == 0
                || s.offset >= self.sections[s.section].spec.data.len() as u64
            {
                return Err(FileParseError::InvalidFileFormat);
            }
        }
        let mut spec = SectionSpec::new(
            name,
            vec![
                0;
                functions
                    .len()
                    .checked_mul(8)
                    .ok_or(FileParseError::ValueTooLarge)?
            ],
        );
        spec.flags = flags;
        spec.alignment = 3;
        let section = self.add_section(segment, spec)?;
        for (i, f) in functions.iter().enumerate() {
            self.add_fixup(&section, i as u64 * 8, f, 0, FixupKind::Va64)?;
        }
        Ok(section)
    }
    /// Creates a scoped initialized TLV template and three-word descriptor.
    /// `bootstrap` must name the libSystem dependency providing `__tlv_bootstrap`.
    /// Caller code accesses the descriptor through Apple's TLV calling convention.
    pub fn add_thread_local(
        &mut self,
        segment: &SegmentId,
        bootstrap: &DependencyId,
        initial: Vec<u8>,
        alignment: u32,
    ) -> Result<SectionId> {
        self.check(&segment.owner, segment.index, self.segments.len())?;
        self.check(&bootstrap.owner, bootstrap.index, self.dependencies.len())?;
        if !self.dyld
            || self.segments[segment.index].protection & 2 == 0
            || self
                .sections
                .iter()
                .any(|s| matches!(s.spec.flags & 255, 17..=21))
            || alignment
                > match self.target {
                    Target::X86_64 => 12,
                    Target::Arm64 => 14,
                }
            || initial.is_empty()
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        let mut template = SectionSpec::new("__thread_data", initial);
        template.flags = 17;
        template.alignment = alignment;
        self.add_section(segment, template)?;
        let mut descriptor = SectionSpec::new("__thread_vars", vec![0; 24]);
        descriptor.flags = 19;
        descriptor.alignment = 3;
        let descriptor = self.add_section(segment, descriptor)?;
        self.add_import("__tlv_bootstrap", bootstrap, &descriptor, 0)?;
        Ok(descriptor)
    }
    /// Adds caller-encoded DWARF CFI to `__TEXT,__eh_frame`.
    /// The caller owns CIE/FDE encodings and relative fixups; synthesis is out of scope.
    pub fn add_unwind(&mut self, text: &SegmentId, data: Vec<u8>) -> Result<SectionId> {
        self.check(&text.owner, text.index, self.segments.len())?;
        if self.segments[text.index].name != "__TEXT" || data.len() < 4 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let mut pos = 0usize;
        while pos < data.len() {
            let length = u32::from_le_bytes(
                data.get(pos..pos + 4)
                    .ok_or(FileParseError::BufferOverflow)?
                    .try_into()
                    .map_err(|_| FileParseError::BufferOverflow)?,
            ) as usize;
            pos = pos
                .checked_add(4)
                .and_then(|p| p.checked_add(length))
                .ok_or(FileParseError::ValueTooLarge)?;
            if length == u32::MAX as usize || pos > data.len() {
                return Err(FileParseError::InvalidFileFormat);
            }
            if length == 0 && pos != data.len() {
                return Err(FileParseError::InvalidFileFormat);
            }
        }
        let mut spec = SectionSpec::new("__eh_frame", data);
        spec.alignment = 3;
        spec.flags = 0x6800000b; // S_COALESCED, live support, no dead strip
                                 // Regular storage preserves the caller's CFI without promising compact unwind synthesis.
        spec.flags = 0;
        self.add_section(text, spec)
    }
}
