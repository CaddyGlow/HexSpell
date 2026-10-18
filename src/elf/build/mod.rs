//! Static and dynamic Linux x86-64 image construction.
//!
//! The writer accepts caller-provided machine code. It does not link object files
//! or generate PLT stubs. Dynamic images use eager import slots and RELA. Builders and handles contain `Rc` tokens and are
//! consequently neither `Send` nor `Sync`; ownership does not affect output bytes.
use crate::elf::ELF;
use crate::errors::{FileParseError, Result};
use alloc::{
    rc::Rc,
    string::{String, ToString},
    vec,
    vec::Vec,
};
mod dynamic;
mod emit;
pub mod layout;
mod runtime;

macro_rules! handle {
    ($name:ident) => {
        /// Opaque identity owned by the builder that created it.
        #[derive(Clone, Debug)]
        pub struct $name {
            owner: Rc<()>,
            index: usize,
        }
    };
}
handle!(SegmentId);
handle!(SectionId);
handle!(SymbolId);

/// ELF loader kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageKind {
    /// Fixed-address static executable.
    Executable,
    /// Linux loader-managed position-independent executable.
    Pie,
    /// Linux shared object with exported global symbols.
    SharedObject,
}
/// Supported executable ABI profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// ELF64, little-endian, Linux AMD64.
    LinuxX86_64,
}
/// Load-segment permissions. Writable executable mappings are rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentSpec {
    /// Read permission.
    pub read: bool,
    /// Write permission.
    pub write: bool,
    /// Execute permission.
    pub execute: bool,
}
impl SegmentSpec {
    /// Readable executable segment.
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    /// Readable writable segment.
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    /// Read-only segment.
    pub const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
}
/// Owned section specification. No on-disk offsets exist until emission.
#[derive(Clone, Debug)]
pub struct SectionSpec {
    /// UTF-8 section name without embedded NUL.
    pub name: String,
    /// File-backed contents; empty for zero-fill sections.
    pub data: Vec<u8>,
    /// Required power-of-two alignment, at most the 4096-byte page size.
    pub alignment: u64,
    /// Zero-filled virtual bytes instead of file-backed storage.
    pub zero_fill: u64,
    /// Whether this is `SHT_NOBITS`, including zero-length zero-fill sections.
    pub is_zero_fill: bool,
}
impl SectionSpec {
    /// Creates an initialized section with byte alignment.
    pub fn new(name: &str, data: Vec<u8>) -> Self {
        Self {
            name: name.to_string(),
            data,
            alignment: 1,
            zero_fill: 0,
            is_zero_fill: false,
        }
    }
    /// Creates a `SHT_NOBITS` section without allocating its virtual contents.
    pub fn zero_fill(name: &str, size: u64, alignment: u64) -> Self {
        Self {
            name: name.to_string(),
            data: Vec::new(),
            alignment,
            zero_fill: size,
            is_zero_fill: true,
        }
    }
}
/// Static symbol binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// Symbol visible only in this image.
    Local,
    /// Globally visible static symbol.
    Global,
    /// Weak definition, overridable by a global symbol.
    Weak,
}
/// ELF symbol visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// Normal symbol lookup.
    Default,
    /// Symbol is not available outside this image.
    Hidden,
    /// Externally visible; internal references bind to this definition.
    Protected,
}
/// Checked AMD64 build-time fixup encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixupKind {
    /// Unsigned little-endian 64-bit target virtual address plus addend.
    Absolute64,
    /// Unsigned little-endian 32-bit target virtual address plus addend.
    Absolute32,
    /// Signed little-endian target plus addend minus address immediately after the four-byte field.
    PcRelative32,
}
/// File/virtual placement of one caller-defined section.
#[derive(Clone, Debug)]
pub struct SectionLayout {
    /// Corresponding builder-owned section identity.
    pub section: SectionId,
    /// File location, absent for virtual-only storage.
    pub file_offset: Option<u64>,
    /// Preferred virtual address, absent for nonallocated sections.
    pub virtual_address: Option<u64>,
    /// Initialized or zero-fill extent.
    pub size: u64,
}
/// Placement of a caller-defined load segment.
#[derive(Clone, Debug)]
pub struct SegmentLayout {
    /// Original segment identity.
    pub segment: SegmentId,
    /// File offset of the mapping.
    pub file_offset: u64,
    /// Preferred mapping address.
    pub virtual_address: u64,
    /// Initialized file extent.
    pub file_size: u64,
    /// Virtual extent including zero-fill.
    pub memory_size: u64,
}
/// Placement report in specification order.
#[derive(Clone, Debug)]
pub struct LayoutReport {
    /// Preferred image base (including the mapped ELF headers).
    pub image_base: u64,
    /// Entry-point virtual address.
    pub entry: u64,
    /// Sections in insertion order.
    pub sections: Vec<SectionLayout>,
    /// Explicit load segments in insertion order.
    pub segments: Vec<SegmentLayout>,
}
#[derive(Clone)]
struct Section {
    spec: SectionSpec,
    segment: Option<usize>,
}
#[derive(Clone)]
struct Symbol {
    name: String,
    section: usize,
    offset: u64,
    size: u64,
    binding: Binding,
    visibility: Visibility,
    version: Option<String>,
}
#[derive(Clone)]
struct Fixup {
    section: usize,
    offset: u64,
    target: usize,
    addend: i64,
    kind: FixupKind,
}
/// Reusable owned specification for a Linux x86-64 executable or shared object.
///
/// A read-only header mapping and nonexecutable GNU stack are emitted automatically.
/// Each explicit segment begins on a page boundary. Zero-fill sections must follow
/// all initialized sections in their segment. Section tables may be omitted.
pub struct ElfBuilder {
    owner: Rc<()>,
    segments: Vec<SegmentSpec>,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    fixups: Vec<Fixup>,
    entry: Option<usize>,
    section_table: bool,
    kind: ImageKind,
    interpreter: Option<String>,
    soname: Option<String>,
    runpath: Option<String>,
    imports: Vec<(String, String, usize)>,
    import_versions: Vec<Option<String>>,
    extra_programs: Vec<(u64, usize)>,
    initializers: Vec<usize>,
    finalizers: Vec<usize>,
    tls: Option<usize>,
    tls_slots: Vec<(usize, u64)>,
    unwind: Option<runtime::Unwind>,
}
impl ElfBuilder {
    /// Creates an empty builder for the selected profile.
    pub fn new(_target: Target) -> Self {
        Self {
            owner: Rc::new(()),
            segments: Vec::new(),
            sections: Vec::new(),
            symbols: Vec::new(),
            fixups: Vec::new(),
            entry: None,
            section_table: true,
            kind: ImageKind::Executable,
            interpreter: None,
            soname: None,
            runpath: None,
            imports: Vec::new(),
            import_versions: Vec::new(),
            extra_programs: Vec::new(),
            initializers: Vec::new(),
            finalizers: Vec::new(),
            tls: None,
            tls_slots: Vec::new(),
            unwind: None,
        }
    }
    /// Selects static executable, PIE, or shared-object output.
    pub fn set_image_kind(&mut self, kind: ImageKind) {
        self.kind = kind;
    }
    /// Sets the explicit absolute interpreter path required for PIE output.
    pub fn set_interpreter(&mut self, path: &str) -> Result<()> {
        if !path.starts_with('/') || path.as_bytes().contains(&0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        self.interpreter = Some(path.into());
        Ok(())
    }
    /// Sets the shared-object install name (`DT_SONAME`).
    pub fn set_soname(&mut self, name: &str) -> Result<()> {
        if name.as_bytes().contains(&0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        self.soname = Some(name.into());
        Ok(())
    }
    /// Sets runtime dependency search paths (`DT_RUNPATH`).
    pub fn set_runpath(&mut self, path: &str) -> Result<()> {
        if path.as_bytes().contains(&0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        self.runpath = Some(path.into());
        Ok(())
    }
    /// Adds an eagerly resolved eight-byte import slot and returns its address symbol.
    ///
    /// Use a PC-relative fixup to address the slot, then indirect through it. The
    /// library name becomes `DT_NEEDED`; use `add_versioned_import_slot` for
    /// dependencies requiring a symbol version. IFUNC imports are unsupported.
    pub fn add_import_slot(&mut self, library: &str, name: &str) -> Result<SymbolId> {
        if library.is_empty()
            || name.is_empty()
            || library.as_bytes().contains(&0)
            || name.as_bytes().contains(&0)
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        let slot_name = alloc::format!("__hexspell_import_{}", self.imports.len());
        if self.symbols.iter().any(|symbol| symbol.name == slot_name) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let segment = self.add_segment(SegmentSpec::RW)?;
        let section = self.add_section(Some(&segment), SectionSpec::new(".got", vec![0; 8]))?;
        let symbol = self.define_symbol(&slot_name, &section, 0, 8, Binding::Local)?;
        self.imports
            .push((library.into(), name.into(), section.index));
        self.import_versions.push(None);
        Ok(symbol)
    }
    /// Adds an import with a required ELF symbol version, e.g. `GLIBC_2.2.5`.
    pub fn add_versioned_import_slot(
        &mut self,
        library: &str,
        name: &str,
        version: &str,
    ) -> Result<SymbolId> {
        if version.is_empty() || version.as_bytes().contains(&0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let symbol = self.add_import_slot(library, name)?;
        if let Some(slot) = self.import_versions.last_mut() {
            *slot = Some(version.into());
        }
        Ok(symbol)
    }
    /// Sets ELF visibility for an existing symbol.
    pub fn set_symbol_visibility(
        &mut self,
        symbol: &SymbolId,
        visibility: Visibility,
    ) -> Result<()> {
        let index = self.check(&symbol.owner, symbol.index, self.symbols.len())?;
        self.symbols[index].visibility = visibility;
        Ok(())
    }
    /// Assigns a default export version. One definition per symbol is supported.
    pub fn set_symbol_version(&mut self, symbol: &SymbolId, version: &str) -> Result<()> {
        let index = self.check(&symbol.owner, symbol.index, self.symbols.len())?;
        if self.symbols[index].binding == Binding::Local
            || version.is_empty()
            || version.as_bytes().contains(&0)
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        self.symbols[index].version = Some(version.into());
        Ok(())
    }
    /// Controls section-table emission. Program loading and build-time fixups do not require it.
    pub fn emit_section_table(&mut self, enabled: bool) {
        self.section_table = enabled;
    }
    /// Adds a page-aligned load segment.
    pub fn add_segment(&mut self, spec: SegmentSpec) -> Result<SegmentId> {
        if spec.write && spec.execute {
            return Err(FileParseError::UnsupportedFeature(
                "writable executable ELF segments".into(),
            ));
        }
        let index = self.segments.len();
        self.segments.push(spec);
        Ok(SegmentId {
            owner: self.owner.clone(),
            index,
        })
    }
    /// Adds a section to a segment, or nonallocated file metadata with `None`.
    pub fn add_section(
        &mut self,
        segment: Option<&SegmentId>,
        spec: SectionSpec,
    ) -> Result<SectionId> {
        let segment = segment
            .map(|id| self.check(&id.owner, id.index, self.segments.len()))
            .transpose()?;
        if (!spec.is_zero_fill && spec.zero_fill != 0)
            || spec.name.as_bytes().contains(&0)
            || !spec.alignment.is_power_of_two()
            || spec.alignment > 4096
            || (spec.is_zero_fill && (!spec.data.is_empty() || segment.is_none()))
        {
            return Err(FileParseError::InvalidFileFormat);
        }
        let index = self.sections.len();
        self.sections.push(Section { spec, segment });
        Ok(SectionId {
            owner: self.owner.clone(),
            index,
        })
    }
    /// Defines a named static symbol at a section-relative byte offset.
    pub fn define_symbol(
        &mut self,
        name: &str,
        section: &SectionId,
        offset: u64,
        size: u64,
        binding: Binding,
    ) -> Result<SymbolId> {
        let section = self.check(&section.owner, section.index, self.sections.len())?;
        if name.as_bytes().contains(&0) || self.symbols.iter().any(|s| s.name == name) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let spec = &self.sections[section].spec;
        let length = if spec.is_zero_fill {
            spec.zero_fill
        } else {
            spec.data.len() as u64
        };
        if offset.checked_add(size).is_none_or(|end| end > length) {
            return Err(FileParseError::BufferOverflow);
        }
        let index = self.symbols.len();
        self.symbols.push(Symbol {
            name: name.into(),
            section,
            offset,
            size,
            binding,
            visibility: Visibility::Default,
            version: None,
        });
        Ok(SymbolId {
            owner: self.owner.clone(),
            index,
        })
    }
    /// Selects an entry symbol; build validates initialized executable storage.
    pub fn set_entry(&mut self, symbol: &SymbolId) -> Result<()> {
        self.entry = Some(self.check(&symbol.owner, symbol.index, self.symbols.len())?);
        Ok(())
    }
    /// Adds a fixup into initialized bytes. Writes must not overlap.
    pub fn add_fixup(
        &mut self,
        section: &SectionId,
        offset: u64,
        target: &SymbolId,
        kind: FixupKind,
        addend: i64,
    ) -> Result<()> {
        let section = self.check(&section.owner, section.index, self.sections.len())?;
        let target = self.check(&target.owner, target.index, self.symbols.len())?;
        let width = if kind == FixupKind::Absolute64 { 8 } else { 4 };
        let end = offset
            .checked_add(width)
            .ok_or(FileParseError::ValueTooLarge)?;
        if end > self.sections[section].spec.data.len() as u64 {
            return Err(FileParseError::BufferOverflow);
        }
        for fixup in &self.fixups {
            let other_width = if fixup.kind == FixupKind::Absolute64 {
                8
            } else {
                4
            };
            if fixup.section == section && offset < fixup.offset + other_width && fixup.offset < end
            {
                return Err(FileParseError::InvalidFileFormat);
            }
        }
        self.fixups.push(Fixup {
            section,
            offset,
            target,
            kind,
            addend,
        });
        Ok(())
    }
    /// Emits and reparses an image without changing the specification.
    pub fn build(&self) -> Result<ELF> {
        Ok(self.build_with_layout()?.0)
    }
    /// Emits an image and its resolved layout.
    pub fn build_with_layout(&self) -> Result<(ELF, LayoutReport)> {
        if self.kind == ImageKind::Executable {
            if !self.imports.is_empty()
                || self.interpreter.is_some()
                || self.soname.is_some()
                || self.runpath.is_some()
                || !self.initializers.is_empty()
                || !self.finalizers.is_empty()
                || self.tls.is_some()
                || self.unwind.is_some()
                || self.symbols.iter().any(|symbol| symbol.version.is_some())
            {
                return Err(FileParseError::UnsupportedFeature(
                    "dynamic metadata in a static executable".into(),
                ));
            }
            emit::build(self)
        } else {
            dynamic::build(self)
        }
    }
    fn check(&self, owner: &Rc<()>, index: usize, length: usize) -> Result<usize> {
        if !Rc::ptr_eq(&self.owner, owner) || index >= length {
            return Err(FileParseError::InvalidFileFormat);
        }
        Ok(index)
    }
}
