//! Dependency-free construction of PE32 and PE32+ images.
//!
//! Builders and handles use an `Rc` ownership token and are therefore not Send or
//! Sync. Independent builders emit identical bytes for identical specifications.
use crate::{
    errors::{FileParseError, Result},
    pe::PE,
};
use alloc::{
    collections::BTreeMap,
    rc::Rc,
    string::{String, ToString},
    vec,
    vec::Vec,
};
mod emit;
/// Target instruction set and optional-header layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// 32-bit Intel image.
    X86,
    /// 64-bit AMD64 image.
    X64,
}
/// Image loader kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageKind {
    /// Executable image.
    Executable,
    /// Dynamic link library image.
    Dll,
}
macro_rules! handle {
    ($name:ident) => {
        #[derive(Clone, Debug)]
        /// Opaque handle valid only for its originating builder.
        pub struct $name {
            owner: Rc<()>,
            index: usize,
        }
    };
}
handle!(SectionId);
handle!(SymbolId);
handle!(ImportId);
/// User-provided section bytes and virtual extent.
#[derive(Clone, Debug)]
pub struct SectionSpec {
    /// Section display name, at most eight non-NUL bytes.
    pub name: String,
    /// Initialized bytes stored in the file.
    pub data: Vec<u8>,
    /// Virtual extent including zero-filled trailing bytes.
    pub virtual_size: u32,
    /// IMAGE_SCN_* permission and content flags.
    pub characteristics: u32,
}
impl SectionSpec {
    /// Creates a section with virtual size equal to its byte length.
    pub fn new(name: &str, data: Vec<u8>, characteristics: u32) -> Self {
        Self {
            name: name.to_string(),
            virtual_size: u32::try_from(data.len()).unwrap_or(u32::MAX),
            data,
            characteristics,
        }
    }
}
/// Address write encoding. Rel32 origin is a section-relative byte offset.
#[derive(Clone, Copy, Debug)]
pub enum FixupKind {
    /// Write a 32-bit relative virtual address.
    Rva32,
    /// Write a 32-bit image virtual address (x86 only).
    Va32,
    /// Write a 64-bit image virtual address (x64 only).
    Va64,
    /// Write a signed displacement from the explicit section-relative origin.
    Rel32 { origin: u32 },
}
#[derive(Clone, Debug)]
/// Destination of an address write.
pub enum FixupTarget {
    /// A caller-defined symbol.
    Symbol(SymbolId),
    /// An import address table slot.
    Import(ImportId),
}
#[derive(Clone, Debug)]
/// Checked address write in initialized caller section bytes.
pub struct Fixup {
    /// Section containing the write.
    pub section: SectionId,
    /// Offset of the first byte to patch within the section.
    pub offset: u32,
    /// Resolved destination.
    pub target: FixupTarget,
    /// Encoding and displacement origin.
    pub kind: FixupKind,
    /// Signed amount added to the resolved address or displacement.
    pub addend: i64,
}
#[derive(Clone, Debug)]
/// TLS template, index and ordered callbacks.
pub struct TlsSpec {
    /// First initialized template byte.
    pub start: SymbolId,
    /// Exclusive template end marker in the same section.
    pub end: SymbolId,
    /// Four writable bytes for the loader TLS index.
    pub index: SymbolId,
    /// Executable callback symbols in invocation order.
    pub callbacks: Vec<SymbolId>,
    /// Additional zero-filled TLS bytes.
    pub zero_fill: u32,
    /// Power-of-two template alignment, at most 8192.
    pub alignment: u32,
}
#[derive(Clone, Debug)]
/// Final address of a symbol or import slot.
pub struct ResolvedLocation {
    /// Relative virtual address.
    pub rva: u32,
    /// Image virtual address including the preferred base.
    pub va: u64,
    /// Initialized file byte offset; absent for virtual-only positions and end markers.
    pub file_offset: Option<usize>,
}
#[derive(Clone, Debug)]
/// Final placement of a caller section.
pub struct ResolvedSection {
    /// Relative virtual address.
    pub rva: u32,
    /// Raw file position (no bytes are occupied when raw_size is zero).
    pub file_offset: usize,
    /// Aligned file allocation.
    pub raw_size: u32,
    /// Virtual extent including zero-filled trailing bytes.
    pub virtual_size: u32,
}
/// Resolved addresses keyed by handles from the originating builder.
pub struct LayoutReport {
    owner: Rc<()>,
    sections: Vec<ResolvedSection>,
    symbols: Vec<ResolvedLocation>,
    imports: Vec<ResolvedLocation>,
}
impl LayoutReport {
    /// Looks up a caller section; foreign handles return None.
    pub fn section(&self, id: &SectionId) -> Option<&ResolvedSection> {
        Rc::ptr_eq(&self.owner, &id.owner)
            .then(|| self.sections.get(id.index))
            .flatten()
    }
    /// Looks up a symbol; foreign handles return None.
    pub fn symbol(&self, id: &SymbolId) -> Option<&ResolvedLocation> {
        Rc::ptr_eq(&self.owner, &id.owner)
            .then(|| self.symbols.get(id.index))
            .flatten()
    }
    /// Looks up an IAT slot; foreign handles return None.
    pub fn import(&self, id: &ImportId) -> Option<&ResolvedLocation> {
        Rc::ptr_eq(&self.owner, &id.owner)
            .then(|| self.imports.get(id.index))
            .flatten()
    }
}
#[derive(Clone, PartialEq, Eq)]
enum ImportName {
    Name(String),
    Ordinal(u16),
}
#[derive(Clone)]
struct Import {
    dll: String,
    name: ImportName,
}
struct Export {
    ordinal: u32,
    name: Option<String>,
    symbol: SymbolId,
}
/// Reusable specification. Failed builds leave this object unchanged.
pub struct PeBuilder {
    owner: Rc<()>,
    target: Target,
    kind: ImageKind,
    /// Preferred base, aligned to 64 KiB. Defaults to 0x400000 / 0x140000000.
    pub image_base: u64,
    /// File alignment, a power of two from 512 to 65536; default 512.
    pub file_alignment: u32,
    /// Virtual alignment, a power of two at least 4096 and file alignment; default 4096.
    pub section_alignment: u32,
    /// IMAGE_SUBSYSTEM_* value; default Windows CUI (3).
    pub subsystem: u16,
    sections: Vec<SectionSpec>,
    symbols: Vec<(SectionId, u32)>,
    imports: Vec<Import>,
    exports: Vec<Export>,
    export_name: String,
    export_base: Option<u32>,
    resources: Option<super::resource::ResourceDirectoryOwned>,
    entry: Option<SymbolId>,
    fixups: Vec<Fixup>,
    tls: Option<TlsSpec>,
    functions: Vec<(SymbolId, SymbolId, SymbolId)>,
}
fn invalid<T>() -> Result<T> {
    Err(FileParseError::InvalidFileFormat)
}
fn u32n(n: usize) -> Result<u32> {
    u32::try_from(n).map_err(|_| FileParseError::ValueTooLarge)
}
fn add(a: u32, b: u32) -> Result<u32> {
    a.checked_add(b).ok_or(FileParseError::ValueTooLarge)
}
fn align(n: u32, a: u32) -> Result<u32> {
    Ok(add(n, a - 1)? & !(a - 1))
}
fn string_ok(s: &str) -> bool {
    !s.is_empty() && !s.as_bytes().contains(&0)
}
impl PeBuilder {
    /// Creates an empty deterministic image specification with zero timestamps.
    pub fn new(target: Target, kind: ImageKind) -> Self {
        Self {
            owner: Rc::new(()),
            target,
            kind,
            image_base: if target == Target::X86 {
                0x400000
            } else {
                0x140000000
            },
            file_alignment: 0x200,
            section_alignment: 0x1000,
            subsystem: 3,
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            export_name: "hexspell.dll".to_string(),
            export_base: None,
            resources: None,
            entry: None,
            fixups: Vec::new(),
            tls: None,
            functions: Vec::new(),
        }
    }
    fn owns(&self, owner: &Rc<()>) -> Result<()> {
        if Rc::ptr_eq(&self.owner, owner) {
            Ok(())
        } else {
            invalid()
        }
    }
    fn symbol_index(&self, s: &SymbolId) -> Result<usize> {
        self.owns(&s.owner)?;
        if s.index >= self.symbols.len() {
            return invalid();
        }
        Ok(s.index)
    }
    /// Appends a caller section. Generated table section names are reserved.
    pub fn add_section(&mut self, s: SectionSpec) -> Result<SectionId> {
        if !string_ok(&s.name)
            || s.name.len() > 8
            || [".idata", ".edata", ".reloc", ".tlsdir", ".pdata", ".rsrc"]
                .contains(&s.name.as_str())
            || s.virtual_size < u32n(s.data.len())?
        {
            return invalid();
        }
        let id = SectionId {
            owner: self.owner.clone(),
            index: self.sections.len(),
        };
        self.sections.push(s);
        Ok(id)
    }
    /// Defines a position within a section, permitting an exclusive end marker.
    pub fn define_symbol(&mut self, section: &SectionId, offset: u32) -> Result<SymbolId> {
        self.owns(&section.owner)?;
        let s = self
            .sections
            .get(section.index)
            .ok_or(FileParseError::InvalidFileFormat)?;
        if offset > s.virtual_size {
            return invalid();
        }
        let id = SymbolId {
            owner: self.owner.clone(),
            index: self.symbols.len(),
        };
        self.symbols.push((section.clone(), offset));
        Ok(id)
    }
    fn executable(&self, id: &SymbolId) -> Result<()> {
        let (s, o) = &self.symbols[self.symbol_index(id)?];
        let sec = &self.sections[s.index];
        if sec.characteristics & 0x20000000 == 0 || *o as usize >= sec.data.len() {
            return invalid();
        }
        Ok(())
    }
    /// Sets an entry point in initialized executable bytes.
    pub fn set_entry_point(&mut self, s: &SymbolId) -> Result<()> {
        self.executable(s)?;
        self.entry = Some(s.clone());
        Ok(())
    }
    /// Sets the nonempty NUL-free DLL export directory name.
    pub fn set_export_name(&mut self, name: &str) -> Result<()> {
        if !string_ok(name) {
            return invalid();
        }
        self.export_name = name.to_string();
        Ok(())
    }
    /// Imports a named function. An exact duplicate reuses its IAT slot.
    pub fn add_import(&mut self, dll: &str, name: &str) -> Result<ImportId> {
        if !string_ok(name) {
            return invalid();
        }
        self.import(dll, ImportName::Name(name.to_string()))
    }
    /// Imports a nonzero ordinal. An exact duplicate reuses its IAT slot.
    pub fn add_import_ordinal(&mut self, dll: &str, ordinal: u16) -> Result<ImportId> {
        if ordinal == 0 {
            return invalid();
        }
        self.import(dll, ImportName::Ordinal(ordinal))
    }
    fn import(&mut self, dll: &str, name: ImportName) -> Result<ImportId> {
        if !string_ok(dll) {
            return invalid();
        }
        let index = if let Some(i) = self
            .imports
            .iter()
            .position(|i| i.dll == dll && i.name == name)
        {
            i
        } else {
            let i = self.imports.len();
            self.imports.push(Import {
                dll: dll.to_string(),
                name,
            });
            i
        };
        Ok(ImportId {
            owner: self.owner.clone(),
            index,
        })
    }
    /// Registers an executable local export with an optional public name.
    pub fn add_export(
        &mut self,
        ordinal: u32,
        name: Option<&str>,
        symbol: &SymbolId,
    ) -> Result<()> {
        self.executable(symbol)?;
        if ordinal == 0
            || ordinal > 65535
            || name.is_some_and(|n| !string_ok(n))
            || self
                .exports
                .iter()
                .any(|e| e.ordinal == ordinal || name.is_some_and(|n| e.name.as_deref() == Some(n)))
        {
            return invalid();
        }
        self.exports.push(Export {
            ordinal,
            name: name.map(ToString::to_string),
            symbol: symbol.clone(),
        });
        Ok(())
    }
    /// Registers a write; overlap, width, and range checks run during build.
    pub fn add_fixup(&mut self, f: Fixup) -> Result<()> {
        self.owns(&f.section.owner)?;
        match &f.target {
            FixupTarget::Symbol(s) => {
                self.symbol_index(s)?;
            }
            FixupTarget::Import(i) => {
                self.owns(&i.owner)?;
                if i.index >= self.imports.len() {
                    return invalid();
                }
            }
        }
        self.fixups.push(f);
        Ok(())
    }
    /// Attaches validated TLS template/index/callback specifications.
    pub fn set_tls(&mut self, t: TlsSpec) -> Result<()> {
        for s in [&t.start, &t.end, &t.index] {
            self.symbol_index(s)?;
        }
        for s in &t.callbacks {
            self.executable(s)?;
        }
        if !t.alignment.is_power_of_two() || t.alignment > 8192 {
            return invalid();
        }
        let (a, ao) = &self.symbols[t.start.index];
        let (b, bo) = &self.symbols[t.end.index];
        if a.index != b.index || ao > bo || *bo as usize > self.sections[a.index].data.len() {
            return invalid();
        }
        let (i, o) = &self.symbols[t.index.index];
        let sec = &self.sections[i.index];
        if sec.characteristics & 0x80000000 == 0 || add(*o, 4)? as usize > sec.data.len() {
            return invalid();
        }
        self.tls = Some(t);
        Ok(())
    }
    /// Registers x64 function bounds and caller-supplied aligned unwind bytes.
    pub fn add_runtime_function(
        &mut self,
        begin: &SymbolId,
        end: &SymbolId,
        unwind: &SymbolId,
    ) -> Result<()> {
        if self.target != Target::X64 {
            return Err(FileParseError::UnsupportedFeature(
                "x86 runtime function".to_string(),
            ));
        }
        self.executable(begin)?;
        self.symbol_index(end)?;
        self.symbol_index(unwind)?;
        let (a, x) = &self.symbols[begin.index];
        let (b, y) = &self.symbols[end.index];
        let (u, o) = &self.symbols[unwind.index];
        if a.index != b.index
            || x >= y
            || *y as usize > self.sections[a.index].data.len()
            || o % 4 != 0
            || add(*o, 4)? as usize > self.sections[u.index].data.len()
        {
            return invalid();
        }
        self.functions
            .push((begin.clone(), end.clone(), unwind.clone()));
        Ok(())
    }
    /// Sets an explicit export ordinal base (1 through 65535).
    pub fn set_export_base(&mut self, base: u32) -> Result<()> {
        if base == 0 || base > 65535 {
            return invalid();
        }
        self.export_base = Some(base);
        Ok(())
    }
    /// Attaches an owned resource tree for serialization into .rsrc.
    pub fn set_resources(&mut self, resources: super::resource::ResourceDirectoryOwned) {
        self.resources = Some(resources);
    }
    /// Builds and reparses a complete image without mutating the specification.
    pub fn build(&self) -> Result<PE> {
        Ok(self.build_with_layout()?.0)
    }
    /// Builds an image and resolves caller handles into final locations.
    pub fn build_with_layout(&self) -> Result<(PE, LayoutReport)> {
        emit::build(self)
    }
}
