//! Thin 64-bit Mach-O construction and opt-in macOS dyld linkage.
//!
//! Output is unsigned and external signing is required before native acceptance.
//! Builders and handles contain `Rc` and are neither Send nor Sync.
use crate::{
    errors::{FileParseError, Result},
    macho::MachO,
};
use alloc::{
    rc::Rc,
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// Supported little-endian CPU profiles.
#[derive(Clone, Copy, Debug)]
pub enum Target {
    /// Intel x86-64 with 4 KiB pages.
    X86_64,
    /// AArch64 with 16 KiB pages; excludes arm64e.
    Arm64,
}
/// macOS deployment version encoded in LC_BUILD_VERSION.
#[derive(Clone, Copy, Debug)]
pub struct Version {
    /// Major deployment version.
    pub major: u16,
    /// Minor deployment version.
    pub minor: u8,
    /// Patch deployment version.
    pub patch: u8,
}
impl Version {
    fn packed(self) -> u32 {
        (u32::from(self.major) << 16) | (u32::from(self.minor) << 8) | u32::from(self.patch)
    }
}
macro_rules! handle {
    ($n:ident) => {
        #[derive(Clone, Debug)]
        /// Opaque builder-owned identity; foreign handles are rejected.
        pub struct $n {
            owner: Rc<()>,
            index: usize,
        }
    };
}
handle!(SegmentId);
handle!(SectionId);
handle!(SymbolId);
handle!(DependencyId);
mod dyld;
/// Segment permissions use VM_PROT_READ/WRITE/EXECUTE (1/2/4).
#[derive(Clone, Debug)]
pub struct SegmentSpec {
    /// Nonempty on-disk name, at most sixteen non-NUL bytes.
    pub name: String,
    /// VM_PROT permission bits; writable executable mappings are rejected.
    pub protection: u32,
}
impl SegmentSpec {
    /// Creates a segment specification.
    pub fn new(name: &str, protection: u32) -> Self {
        Self {
            name: name.to_string(),
            protection,
        }
    }
}
/// Section content. Zero-fill sections have no file payload.
#[derive(Clone, Debug)]
pub struct SectionSpec {
    /// Nonempty on-disk name, at most sixteen non-NUL bytes.
    pub name: String,
    /// Initialized file bytes.
    pub data: Vec<u8>,
    /// Virtual zero-fill size, mutually exclusive with initialized bytes.
    pub zero_fill: u64,
    /// Base-two alignment exponent, at most the target page exponent.
    pub alignment: u32,
    /// Regular, zero-fill, initializer/terminator and scoped TLV section flags.
    pub flags: u32,
}
impl SectionSpec {
    /// Creates an initialized regular section.
    pub fn new(name: &str, data: Vec<u8>) -> Self {
        Self {
            name: name.to_string(),
            data,
            zero_fill: 0,
            alignment: 0,
            flags: 0,
        }
    }
    /// Creates a virtual-only zero-fill section.
    pub fn zero_fill(name: &str, size: u64) -> Self {
        Self {
            name: name.to_string(),
            data: Vec::new(),
            zero_fill: size,
            alignment: 0,
            flags: 1,
        }
    }
}
/// Resolved placement; virtual-only sections have no file offset.
#[derive(Clone, Debug)]
pub struct SectionLayout {
    /// Absolute offset in the emitted file.
    pub file_offset: Option<u64>,
    /// Preferred virtual address.
    pub virtual_address: u64,
    /// Virtual extent in bytes.
    pub size: u64,
}
/// Resolved segment mapping.
#[derive(Clone, Debug)]
pub struct SegmentLayout {
    /// Absolute offset in the emitted file.
    pub file_offset: u64,
    /// Initialized mapping extent in bytes.
    pub file_size: u64,
    /// Preferred virtual address.
    pub virtual_address: u64,
    /// Page-rounded virtual mapping extent.
    pub virtual_size: u64,
}
/// Unsigned image layout in insertion order.
#[derive(Clone, Debug)]
pub struct Layout {
    owner: Rc<()>,
    revision: usize,
    /// Section placements in builder insertion order.
    pub sections: Vec<SectionLayout>,
    /// User segment placements in builder insertion order, excluding generated LINKEDIT.
    pub segments: Vec<SegmentLayout>,
    /// LC_MAIN entry file offset when configured.
    pub entry_file_offset: Option<u64>,
}
/// Build-time address encoding; dyld mode records Va64 writes as chained rebases.
#[derive(Clone, Copy, Debug)]
pub enum FixupKind {
    /// Preferred 64-bit VA; dyld mode emits a runtime rebase for writable aligned slots.
    Va64,
    /// Signed displacement from this field, for caller-encoded unwind metadata.
    PcRel32,
    /// x86-64 signed displacement from an explicit section-relative origin.
    Rel32 { origin: u64 },
    /// arm64 B/BL instruction, relative to the instruction address.
    Arm64Branch26,
    /// arm64 ADRP instruction, relative to the instruction's 4 KiB page.
    Arm64Page21,
    /// arm64 unshifted ADD-immediate instruction targeting the low twelve VA bits.
    Arm64PageOffset12,
}
struct Fixup {
    section: usize,
    offset: u64,
    symbol: usize,
    addend: i64,
    kind: FixupKind,
}
struct Section {
    segment: usize,
    spec: SectionSpec,
}
struct Symbol {
    name: String,
    section: usize,
    offset: u64,
}
/// Reusable executable/dylib builder with an optional macOS 13+ dyld profile.
pub struct MachOBuilder {
    owner: Rc<()>,
    revision: usize,
    target: Target,
    deployment: Version,
    install_name: Option<String>,
    segments: Vec<SegmentSpec>,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    fixups: Vec<Fixup>,
    entry: Option<(usize, u64)>,
    dyld: bool,
    dependencies: Vec<String>,
    rpaths: Vec<String>,
    imports: Vec<(String, usize, usize, u64)>,
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or(FileParseError::ValueTooLarge)
}
fn align(a: u64, b: u64) -> Result<u64> {
    Ok(add(a, b - 1)? & !(b - 1))
}
fn name(n: &str) -> Result<()> {
    if n.is_empty() || n.len() > 16 || n.as_bytes().contains(&0) {
        Err(FileParseError::InvalidFileFormat)
    } else {
        Ok(())
    }
}
fn u32v(v: u64) -> Result<u32> {
    u32::try_from(v).map_err(|_| FileParseError::ValueTooLarge)
}
fn w32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn wn(b: &mut [u8], o: usize, n: &str) {
    b[o..o + n.len()].copy_from_slice(n.as_bytes());
}
impl MachOBuilder {
    /// Creates an unsigned executable specification for an explicit macOS target.
    pub fn new(target: Target, deployment: Version) -> Self {
        Self {
            owner: Rc::new(()),
            revision: 0,
            target,
            deployment,
            install_name: None,
            segments: Vec::new(),
            sections: Vec::new(),
            symbols: Vec::new(),
            fixups: Vec::new(),
            entry: None,
            dyld: false,
            dependencies: Vec::new(),
            rpaths: Vec::new(),
            imports: Vec::new(),
        }
    }
    /// Creates a dylib with a deterministic LC_ID_DYLIB command.
    /// Enable dyld to emit exports, chained binding and pointer rebasing metadata.
    pub fn new_dylib(target: Target, deployment: Version, install_name: &str) -> Result<Self> {
        if install_name.is_empty() || install_name.as_bytes().contains(&0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let mut builder = Self::new(target, deployment);
        builder.install_name = Some(install_name.to_string());
        Ok(builder)
    }
    fn check(&self, owner: &Rc<()>, index: usize, len: usize) -> Result<()> {
        if !Rc::ptr_eq(&self.owner, owner) || index >= len {
            Err(FileParseError::InvalidFileFormat)
        } else {
            Ok(())
        }
    }
    /// Adds a unique named segment after validating its permissions.
    pub fn add_segment(&mut self, spec: SegmentSpec) -> Result<SegmentId> {
        name(&spec.name)?;
        if spec.name == "__LINKEDIT"
            || spec.name == "__PAGEZERO"
            || spec.protection & !7 != 0
            || spec.protection & 6 == 6
            || self.segments.iter().any(|s| s.name == spec.name)
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        let index = self.segments.len();
        self.segments.push(spec);
        self.revision += 1;
        Ok(SegmentId {
            owner: self.owner.clone(),
            index,
        })
    }
    /// Adds a section owned by a segment from this builder.
    pub fn add_section(&mut self, segment: &SegmentId, spec: SectionSpec) -> Result<SectionId> {
        self.check(&segment.owner, segment.index, self.segments.len())?;
        name(&spec.name)?;
        if spec.alignment
            > match self.target {
                Target::X86_64 => 12,
                Target::Arm64 => 14,
            }
            || !matches!(spec.flags & 255, 0 | 1 | 9 | 10 | 17 | 18 | 19 | 20 | 21)
            || (spec.zero_fill != 0 && !spec.data.is_empty())
            || (matches!(spec.flags & 255, 1 | 18) && !spec.data.is_empty())
            || (spec.zero_fill != 0 && !matches!(spec.flags & 255, 1 | 18))
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        let index = self.sections.len();
        self.revision += 1;
        self.sections.push(Section {
            segment: segment.index,
            spec,
        });
        Ok(SectionId {
            owner: self.owner.clone(),
            index,
        })
    }
    /// Selects an entry within initialized executable section bytes.
    pub fn set_entry(&mut self, section: &SectionId, offset: u64) -> Result<()> {
        self.check(&section.owner, section.index, self.sections.len())?;
        if self.install_name.is_some() {
            return Err(FileParseError::InvalidFileFormat);
        }
        let s = &self.sections[section.index];
        if offset >= s.spec.data.len() as u64 || self.segments[s.segment].protection & 4 == 0 {
            return Err(FileParseError::InvalidFileFormat);
        }
        self.entry = Some((section.index, offset));
        self.revision += 1;
        Ok(())
    }
    /// Adds an external defined symbol; offsets may name the section end.
    pub fn add_symbol(&mut self, name: &str, section: &SectionId, offset: u64) -> Result<SymbolId> {
        self.check(&section.owner, section.index, self.sections.len())?;
        let s = &self.sections[section.index].spec;
        if name.is_empty()
            || self.symbols.iter().any(|s| s.name == name)
            || name.as_bytes().contains(&0)
            || offset > add(s.data.len() as u64, s.zero_fill)?
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        let index = self.symbols.len();
        self.revision += 1;
        self.symbols.push(Symbol {
            name: name.to_string(),
            section: section.index,
            offset,
        });
        Ok(SymbolId {
            owner: self.owner.clone(),
            index,
        })
    }
    /// Adds a checked build-time write. Writes may not overlap or target virtual-only bytes.
    pub fn add_fixup(
        &mut self,
        section: &SectionId,
        offset: u64,
        symbol: &SymbolId,
        addend: i64,
        kind: FixupKind,
    ) -> Result<()> {
        self.check(&section.owner, section.index, self.sections.len())?;
        self.check(&symbol.owner, symbol.index, self.symbols.len())?;
        let width = if matches!(kind, FixupKind::Va64) {
            8
        } else {
            4
        };
        let end = add(offset, width)?;
        if end > self.sections[section.index].spec.data.len() as u64 {
            return Err(FileParseError::BufferOverflow);
        }
        match (self.target, kind) {
            (_, FixupKind::Va64 | FixupKind::PcRel32)
            | (Target::X86_64, FixupKind::Rel32 { .. })
            | (
                Target::Arm64,
                FixupKind::Arm64Branch26 | FixupKind::Arm64Page21 | FixupKind::Arm64PageOffset12,
            ) => {}
            _ => {
                return Err(FileParseError::UnsupportedFeature(
                    "fixup target mismatch".to_string(),
                ))
            }
        }
        if let FixupKind::Rel32 { origin } = kind {
            if origin > self.sections[section.index].spec.data.len() as u64 {
                return Err(FileParseError::BufferOverflow);
            }
        }
        if self
            .imports
            .iter()
            .any(|(_, _, s, o)| *s == section.index && offset < *o + 8 && *o < end)
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        for f in &self.fixups {
            let existing_width = if matches!(f.kind, FixupKind::Va64) {
                8
            } else {
                4
            };
            if f.section == section.index
                && offset < add(f.offset, existing_width)?
                && f.offset < end
            {
                return Err(FileParseError::InvalidFileFormat);
            }
        }
        self.fixups.push(Fixup {
            section: section.index,
            offset,
            symbol: symbol.index,
            addend,
            kind,
        });
        self.revision += 1;
        Ok(())
    }
    /// Resolves a symbol handle through this builder's current layout.
    pub fn symbol_address(&self, symbol: &SymbolId, layout: &Layout) -> Result<u64> {
        self.check(&symbol.owner, symbol.index, self.symbols.len())?;
        if !Rc::ptr_eq(&self.owner, &layout.owner) || self.revision != layout.revision {
            return Err(FileParseError::InvalidFileFormat);
        }
        let s = &self.symbols[symbol.index];
        add(
            layout
                .sections
                .get(s.section)
                .ok_or(FileParseError::InvalidFileFormat)?
                .virtual_address,
            s.offset,
        )
    }
    /// Emits and reparses an unsigned image without mutating the specification.
    pub fn build(&self) -> Result<MachO> {
        self.build_with_layout().map(|v| v.0)
    }
    /// Emits an image and a placement snapshot; stale snapshots are rejected by symbol_address.
    pub fn build_with_layout(&self) -> Result<(MachO, Layout)> {
        if self.segments.is_empty() || self.sections.len() > 255 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let page = match self.target {
            Target::X86_64 => 4096,
            Target::Arm64 => 16384,
        };
        let base = 0x1_0000_0000u64;
        self.validate_dyld()?;
        let has_symbols = !self.symbols.is_empty() || self.dyld;
        let dylib_command_size = if let Some(name) = &self.install_name {
            align(add(25, name.len() as u64)?, 8)?
        } else {
            0
        };
        let extra = self.dyld_command_size()?;
        let commands = add(
            extra,
            add(
                dylib_command_size,
                add(
                    add(
                        self.segments.len() as u64 * 72,
                        self.sections.len() as u64 * 80,
                    )?,
                    24 + if self.entry.is_some() { 24 } else { 0 }
                        + if has_symbols { 96 } else { 0 },
                )?,
            )?,
        )?;
        // Reserve room for external codesign to append LC_CODE_SIGNATURE.
        let mut file = if self.dyld {
            align(add(add(32, commands)?, 256)?, 16)?
        } else {
            add(32, commands)?
        };
        let mut va = base;
        let mut segments = Vec::new();
        let mut sections = vec![
            SectionLayout {
                file_offset: None,
                virtual_address: 0,
                size: 0
            };
            self.sections.len()
        ];
        for (i, _) in self.segments.iter().enumerate() {
            let start = if i == 0 { 0 } else { align(file, page)? };
            file = file.max(start);
            let mut memory = file - start;
            let mut virtual_only = false;
            for (j, s) in self
                .sections
                .iter()
                .enumerate()
                .filter(|(_, s)| s.segment == i)
            {
                let alignment = 1u64 << s.spec.alignment;
                let size = add(s.spec.data.len() as u64, s.spec.zero_fill)?;
                memory = align(memory, alignment)?;
                let off = if matches!(s.spec.flags & 255, 1 | 18) {
                    virtual_only = true;
                    None
                } else {
                    if virtual_only {
                        return Err(FileParseError::InvalidFileFormat);
                    }
                    file = add(start, memory)?;
                    let off = file;
                    file = add(file, size)?;
                    Some(off)
                };
                sections[j] = SectionLayout {
                    file_offset: off,
                    virtual_address: add(va, memory)?,
                    size,
                };
                memory = add(memory, size)?;
            }
            let virtual_size = align(memory, page)?;
            segments.push(SegmentLayout {
                file_offset: start,
                file_size: file - start,
                virtual_address: va,
                virtual_size,
            });
            va = add(va, virtual_size)?;
        }
        let symoff = align(file, page)?;
        let stroff = add(symoff, self.symbols.len() as u64 * 16)?;
        let mut strings = vec![0];
        let mut strindices = Vec::new();
        for s in &self.symbols {
            strindices.push(u32v(strings.len() as u64)?);
            strings.extend_from_slice(s.name.as_bytes());
            strings.push(0);
        }
        let (mut chained, exports) = self.dyld_blobs(&sections, &segments, page)?;
        let strings_end = add(stroff, strings.len() as u64)?;
        let chain_offset = align(strings_end, 8)?;
        let exports_offset = align(add(chain_offset, chained.len() as u64)?, 8)?;
        let total = if self.dyld {
            add(exports_offset, exports.len() as u64)?
        } else if has_symbols {
            add(stroff, strings.len() as u64)?
        } else {
            file
        };
        if has_symbols {
            add(va, align(total - symoff, page)?)?;
        }
        u32v(total)?;
        let mut b = vec![0; usize::try_from(total).map_err(|_| FileParseError::ValueTooLarge)?];
        w32(&mut b, 0, 0xfeedfacf);
        w32(
            &mut b,
            4,
            match self.target {
                Target::X86_64 => 0x01000007,
                Target::Arm64 => 0x0100000c,
            },
        );
        w32(
            &mut b,
            8,
            match self.target {
                Target::X86_64 => 3,
                Target::Arm64 => 0,
            },
        );
        w32(&mut b, 12, if self.install_name.is_some() { 6 } else { 2 });
        w32(
            &mut b,
            16,
            u32v(
                self.segments.len() as u64
                    + 1
                    + u64::from(self.entry.is_some())
                    + u64::from(self.install_name.is_some())
                    + if has_symbols { 2 } else { 0 }
                    + self.dyld_command_count(),
            )?,
        );
        w32(&mut b, 20, u32v(commands)?);
        w32(
            &mut b,
            24,
            if self.dyld {
                0x85 | if self.sections.iter().any(|s| s.spec.flags & 255 == 19) {
                    0x800000
                } else {
                    0
                } | if self.install_name.is_none() {
                    0x200000
                } else {
                    0
                }
            } else {
                0
            },
        );
        let mut c = 32;
        self.emit_dyld_commands(
            &mut b,
            &mut c,
            chain_offset,
            chained.len(),
            exports_offset,
            exports.len(),
        )?;
        let mut section_numbers = vec![0u8; self.sections.len()];
        let mut ordinal = 0u8;
        for (i, s) in self.segments.iter().enumerate() {
            let count = self.sections.iter().filter(|s| s.segment == i).count();
            let len = 72 + count * 80;
            let l = &segments[i];
            w32(&mut b, c, 0x19);
            w32(&mut b, c + 4, len as u32);
            wn(&mut b, c + 8, &s.name);
            w64(&mut b, c + 24, l.virtual_address);
            w64(&mut b, c + 32, l.virtual_size);
            w64(&mut b, c + 40, l.file_offset);
            w64(&mut b, c + 48, l.file_size);
            w32(&mut b, c + 56, s.protection);
            w32(&mut b, c + 60, s.protection);
            w32(&mut b, c + 64, count as u32);
            let mut p = c + 72;
            for (j, sec) in self
                .sections
                .iter()
                .enumerate()
                .filter(|(_, s)| s.segment == i)
            {
                ordinal += 1;
                section_numbers[j] = ordinal;
                let l = &sections[j];
                wn(&mut b, p, &sec.spec.name);
                wn(&mut b, p + 16, &s.name);
                w64(&mut b, p + 32, l.virtual_address);
                w64(&mut b, p + 40, l.size);
                w32(&mut b, p + 48, u32v(l.file_offset.unwrap_or(0))?);
                w32(&mut b, p + 52, sec.spec.alignment);
                w32(&mut b, p + 64, sec.spec.flags);
                if let Some(o) = l.file_offset {
                    let o = o as usize;
                    b[o..o + sec.spec.data.len()].copy_from_slice(&sec.spec.data);
                }
                p += 80;
            }
            c += len;
        }
        w32(&mut b, c, 0x32);
        w32(&mut b, c + 4, 24);
        w32(&mut b, c + 8, 1);
        w32(&mut b, c + 12, self.deployment.packed());
        w32(&mut b, c + 16, self.deployment.packed());
        c += 24;
        if let Some(name) = &self.install_name {
            w32(&mut b, c, 0xd);
            w32(&mut b, c + 4, u32v(dylib_command_size)?);
            w32(&mut b, c + 8, 24);
            w32(&mut b, c + 16, 0x10000);
            w32(&mut b, c + 20, 0x10000);
            wn(&mut b, c + 24, name);
            c += dylib_command_size as usize;
        }
        let entry = self
            .entry
            .map(|(s, o)| add(sections[s].file_offset.unwrap_or(0), o))
            .transpose()?;
        if let Some(e) = entry {
            w32(&mut b, c, 0x80000028);
            w32(&mut b, c + 4, 24);
            w64(&mut b, c + 8, e);
            c += 24;
        }
        if has_symbols {
            w32(&mut b, c, 0x19);
            w32(&mut b, c + 4, 72);
            wn(&mut b, c + 8, "__LINKEDIT");
            w64(&mut b, c + 24, va);
            w64(&mut b, c + 32, align(total - symoff, page)?);
            w64(&mut b, c + 40, symoff);
            w64(&mut b, c + 48, total - symoff);
            w32(&mut b, c + 56, 1);
            w32(&mut b, c + 60, 1);
            c += 72;
            w32(&mut b, c, 2);
            w32(&mut b, c + 4, 24);
            w32(&mut b, c + 8, u32v(symoff)?);
            w32(&mut b, c + 12, self.symbols.len() as u32);
            w32(&mut b, c + 16, u32v(stroff)?);
            w32(&mut b, c + 20, u32v(strings.len() as u64)?);
            for (i, s) in self.symbols.iter().enumerate() {
                let p = symoff as usize + i * 16;
                w32(&mut b, p, strindices[i]);
                b[p + 4] = 0x0f;
                b[p + 5] = section_numbers[s.section];
                w64(
                    &mut b,
                    p + 8,
                    add(sections[s.section].virtual_address, s.offset)?,
                );
            }
            b[stroff as usize..strings_end as usize].copy_from_slice(&strings);
        }
        for f in &self.fixups {
            let source = &sections[f.section];
            let symbol = &self.symbols[f.symbol];
            let target = i128::from(add(
                sections[symbol.section].virtual_address,
                symbol.offset,
            )?) + i128::from(f.addend);
            let target = u64::try_from(target).map_err(|_| FileParseError::ValueTooLarge)?;
            let address = add(source.virtual_address, f.offset)?;
            let offset = add(
                source
                    .file_offset
                    .ok_or(FileParseError::InvalidFileFormat)?,
                f.offset,
            )? as usize;
            match f.kind {
                FixupKind::Va64 => w64(&mut b, offset, target),
                FixupKind::PcRel32 => {
                    let delta = i128::from(target) - i128::from(address);
                    w32(
                        &mut b,
                        offset,
                        i32::try_from(delta).map_err(|_| FileParseError::ValueTooLarge)? as u32,
                    );
                }
                FixupKind::Rel32 { origin } => {
                    let displacement =
                        i128::from(target) - i128::from(add(source.virtual_address, origin)?);
                    let displacement =
                        i32::try_from(displacement).map_err(|_| FileParseError::ValueTooLarge)?;
                    w32(&mut b, offset, displacement as u32);
                }
                kind => {
                    if address & 3 != 0 {
                        return Err(FileParseError::InvalidFileFormat);
                    }
                    let instruction = u32::from_le_bytes(
                        b[offset..offset + 4]
                            .try_into()
                            .map_err(|_| FileParseError::BufferOverflow)?,
                    );
                    let encoded = match kind {
                        FixupKind::Arm64Branch26 => {
                            if instruction & 0x7c000000 != 0x14000000 || target & 3 != 0 {
                                return Err(FileParseError::InvalidFileFormat);
                            }
                            let delta = i128::from(target) - i128::from(address);
                            if !(-(1i128 << 27)..(1i128 << 27)).contains(&delta) {
                                return Err(FileParseError::ValueTooLarge);
                            }
                            (instruction & 0xfc000000) | (((delta >> 2) as u32) & 0x03ffffff)
                        }
                        FixupKind::Arm64Page21 => {
                            if instruction & 0x9f000000 != 0x90000000 {
                                return Err(FileParseError::InvalidFileFormat);
                            }
                            let delta =
                                (i128::from(target & !4095) - i128::from(address & !4095)) >> 12;
                            if !(-(1i128 << 20)..(1i128 << 20)).contains(&delta) {
                                return Err(FileParseError::ValueTooLarge);
                            }
                            let immediate = (delta as u32) & 0x1fffff;
                            (instruction & !0x60ffffe0)
                                | ((immediate & 3) << 29)
                                | ((immediate >> 2) << 5)
                        }
                        FixupKind::Arm64PageOffset12 => {
                            if instruction & 0x7fc00000 != 0x11000000 {
                                return Err(FileParseError::InvalidFileFormat);
                            }
                            (instruction & !0x003ffc00) | (((target & 4095) as u32) << 10)
                        }
                        _ => return Err(FileParseError::InvalidFileFormat),
                    };
                    w32(&mut b, offset, encoded);
                }
            }
        }
        if self.dyld {
            self.emit_chained_pointers(&mut b, &sections, &segments, page, &mut chained)?;
            b[chain_offset as usize..chain_offset as usize + chained.len()]
                .copy_from_slice(&chained);
            b[exports_offset as usize..].copy_from_slice(&exports);
        }
        if self.dyld {
            // Deterministic content identity, not a cryptographic integrity digest.
            let mut hashes = [0x811c9dc5u32, 0x9e3779b9, 0x85ebca6b, 0xc2b2ae35];
            for byte in &b {
                for (i, h) in hashes.iter_mut().enumerate() {
                    *h = (*h ^ u32::from(*byte))
                        .wrapping_mul(0x01000193u32.wrapping_add(i as u32 * 2));
                }
            }
            let mut pos = 32;
            while pos < 32 + commands as usize {
                let cmd = u32::from_le_bytes(
                    b[pos..pos + 4]
                        .try_into()
                        .map_err(|_| FileParseError::BufferOverflow)?,
                );
                let len = u32::from_le_bytes(
                    b[pos + 4..pos + 8]
                        .try_into()
                        .map_err(|_| FileParseError::BufferOverflow)?,
                ) as usize;
                if cmd == 0x1b {
                    for (i, h) in hashes.iter().enumerate() {
                        w32(&mut b, pos + 8 + i * 4, *h);
                    }
                    b[pos + 14] = (b[pos + 14] & 15) | 0x40;
                    b[pos + 16] = (b[pos + 16] & 63) | 0x80;
                    break;
                }
                pos += len;
            }
        }
        Ok((
            MachO::from_buffer(b)?,
            Layout {
                owner: self.owner.clone(),
                revision: self.revision,
                sections,
                segments,
                entry_file_offset: entry,
            },
        ))
    }
}
