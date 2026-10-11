//! Reviewed, assembler-free Windows machine code used by the examples.
use hexspell::{
    errors::FileParseError,
    pe::{build::*, PE},
};
const CODE: u32 = 0x60000020;
const READ: u32 = 0x40000040;
const WRITE: u32 = 0xc0000040;
fn utf16(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}
fn patch(
    builder: &mut PeBuilder,
    section: &SectionId,
    offset: usize,
    target: FixupTarget,
    kind: FixupKind,
) -> Result<(), FileParseError> {
    builder.add_fixup(Fixup {
        section: section.clone(),
        offset: offset as u32,
        target,
        kind,
        addend: 0,
    })
}
pub fn target(value: &str) -> Result<Target, &'static str> {
    match value {
        "x86" => Ok(Target::X86),
        "x64" => Ok(Target::X64),
        _ => Err("target must be x86 or x64"),
    }
}
pub fn dll(target: Target) -> Result<PE, FileParseError> {
    let mut b = PeBuilder::new(target, ImageKind::Dll);
    b.image_base = if target == Target::X86 {
        0x10000000
    } else {
        0x180000000
    };
    b.set_export_name("hexspell_demo.dll")?;
    let greeting = b.add_section(SectionSpec::new(".rdata", utf16("Hello"), READ))?;
    let greeting = b.define_symbol(&greeting, 0)?;
    let pointer_width = if target == Target::X86 { 4 } else { 8 };
    let slot = b.add_section(SectionSpec::new(".ptr", vec![0; pointer_width], READ))?;
    let slot_symbol = b.define_symbol(&slot, 0)?;
    patch(
        &mut b,
        &slot,
        0,
        FixupTarget::Symbol(greeting),
        if target == Target::X86 {
            FixupKind::Va32
        } else {
            FixupKind::Va64
        },
    )?;
    let (code, add, get, version) = if target == Target::X86 {
        // DllMain: mov eax,1; ret 12. Add: mov eax,[esp+4]; add eax,[esp+8]; ret 8.
        // GetGreeting: mov eax,[absolute slot]; ret. GetVersion: mov eax,1; ret.
        (
            vec![
                0xb8, 1, 0, 0, 0, 0xc2, 12, 0, 0x8b, 0x44, 0x24, 4, 0x03, 0x44, 0x24, 8, 0xc2, 8,
                0, 0xa1, 0, 0, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3,
            ],
            8,
            19,
            25,
        )
    } else {
        // Leaf functions use only volatile registers and leave RSP unchanged.
        // DllMain: mov eax,1; ret. Add: lea eax,[rcx+rdx]; ret.
        // GetGreeting: mov rax,[rip+slot]; ret. GetVersion: mov eax,1; ret.
        (
            vec![
                0xb8, 1, 0, 0, 0, 0xc3, 0x8d, 0x04, 0x11, 0xc3, 0x48, 0x8b, 0x05, 0, 0, 0, 0, 0xc3,
                0xb8, 1, 0, 0, 0, 0xc3,
            ],
            6,
            10,
            18,
        )
    };
    let text = b.add_section(SectionSpec::new(".text", code, CODE))?;
    let entry = b.define_symbol(&text, 0)?;
    b.set_entry_point(&entry)?;
    for (ordinal, name, offset) in [
        (1, Some("Add"), add),
        (2, Some("GetGreeting"), get),
        (3, None, version),
    ] {
        let symbol = b.define_symbol(&text, offset)?;
        b.add_export(ordinal, name, &symbol)?;
    }
    patch(
        &mut b,
        &text,
        if target == Target::X86 { 20 } else { 13 },
        FixupTarget::Symbol(slot_symbol),
        if target == Target::X86 {
            FixupKind::Va32
        } else {
            FixupKind::Rel32 { origin: 17 }
        },
    )?;
    b.build()
}
fn hello_resources() -> Result<hexspell::pe::resource::ResourceDirectoryOwned, FileParseError> {
    use hexspell::pe::resource::{
        icon::{Icon, IconImage},
        strings::StringTable,
        version::VersionBlock,
        ResourceData, ResourceDirectoryOwned, ResourceKey, ResourceNode,
    };
    let mut resources = ResourceDirectoryOwned::default();
    fn insert(
        resources: &mut ResourceDirectoryOwned,
        kind: u32,
        bytes: Vec<u8>,
    ) -> Result<(), FileParseError> {
        resources.insert(
            &[ResourceKey::Id(kind)],
            ResourceNode::Directory(ResourceDirectoryOwned::default()),
        )?;
        resources.insert(
            &[ResourceKey::Id(kind), ResourceKey::Id(1)],
            ResourceNode::Directory(ResourceDirectoryOwned::default()),
        )?;
        resources.insert(
            &[
                ResourceKey::Id(kind),
                ResourceKey::Id(1),
                ResourceKey::Id(1033),
            ],
            ResourceNode::Data(ResourceData {
                bytes,
                code_page: 0,
                reserved: 0,
            }),
        )
    }
    insert(&mut resources,24, br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="HexSpell.Hello" type="win32"/><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>"#.to_vec())?;
    insert(&mut resources, 10, b"HexSpell generated resource".to_vec())?;
    let mut strings = StringTable::default();
    strings.slots[1] = "Hello resource".encode_utf16().collect();
    insert(&mut resources, 6, strings.serialize()?)?;
    // VS_FIXEDFILEINFO: signature, structure version, file/product 1.0.0.0,
    // valid flags mask, no flags, NT Windows32 OS, application type, zero date.
    let fixed = [
        0xfeef04bd_u32,
        0x10000,
        0x10000,
        0,
        0x10000,
        0,
        0x3f,
        0,
        0x40004,
        1,
        0,
        0,
        0,
    ];
    fn block(
        key: &str,
        value_type: u16,
        value: Vec<u8>,
        children: Vec<VersionBlock>,
    ) -> VersionBlock {
        VersionBlock {
            key: key.encode_utf16().collect(),
            value_type,
            value,
            children,
        }
    }
    let file_description = block(
        "FileDescription",
        1,
        utf16("HexSpell generated Hello"),
        vec![],
    );
    let string_table = block("040904B0", 1, vec![], vec![file_description]);
    let string_info = block("StringFileInfo", 1, vec![], vec![string_table]);
    let translation = block("Translation", 0, vec![0x09, 0x04, 0xb0, 0x04], vec![]);
    let var_info = block("VarFileInfo", 1, vec![], vec![translation]);
    let version = VersionBlock {
        key: "VS_VERSION_INFO".encode_utf16().collect(),
        value_type: 0,
        value: fixed.into_iter().flat_map(u32::to_le_bytes).collect(),
        children: vec![string_info, var_info],
    };
    insert(&mut resources, 16, version.serialize()?)?;
    // One opaque red 1x1 32-bit DIB icon: BITMAPINFOHEADER, BGRA pixel, AND mask.
    let mut dib = Vec::new();
    for value in [40u32, 1, 2] {
        dib.extend_from_slice(&value.to_le_bytes());
    }
    dib.extend_from_slice(&1u16.to_le_bytes());
    dib.extend_from_slice(&32u16.to_le_bytes());
    for value in [0u32, 4, 0, 0, 0, 0] {
        dib.extend_from_slice(&value.to_le_bytes());
    }
    dib.extend_from_slice(&[0, 0, 255, 255, 0, 0, 0, 0]);
    let icon = Icon {
        images: vec![IconImage {
            width: 1,
            height: 1,
            color_count: 0,
            reserved: 0,
            planes: 1,
            bit_count: 32,
            bytes: dib,
        }],
    };
    resources.set_icon(ResourceKey::Id(1), 1033, &icon)?;
    Ok(resources)
}
pub fn hello(target: Target) -> Result<PE, FileParseError> {
    hello_with_tls(target, true)
}
pub fn hello_with_tls(target: Target, callback_enabled: bool) -> Result<PE, FileParseError> {
    hello_with_options(target, callback_enabled, false)
}
pub fn hello_with_options(
    target: Target,
    callback_enabled: bool,
    conflicting_base: bool,
) -> Result<PE, FileParseError> {
    let mut b = PeBuilder::new(target, ImageKind::Executable);
    if target == Target::X64 {
        b.image_base = 0x150000000;
    }
    if conflicting_base {
        b.image_base = 0x7ffe0000;
    }
    b.subsystem = 2;
    let message = b.add_import("USER32.dll", "MessageBoxW")?;
    let exit = b.add_import("KERNEL32.dll", "ExitProcess")?;
    let data = b.add_section(SectionSpec::new(".data", vec![0; 8], WRITE))?;
    let index = b.define_symbol(&data, 0)?;
    let flag = b.define_symbol(&data, 4)?;
    let strings = b.add_section(SectionSpec::new(".rdata", utf16("Hello"), READ))?;
    let greeting = b.define_symbol(&strings, 0)?;
    let slot = b.add_section(SectionSpec::new(
        ".ptr",
        vec![0; if target == Target::X86 { 4 } else { 8 }],
        READ,
    ))?;
    let pointer = b.define_symbol(&slot, 0)?;
    patch(
        &mut b,
        &slot,
        0,
        FixupTarget::Symbol(greeting),
        if target == Target::X86 {
            FixupKind::Va32
        } else {
            FixupKind::Va64
        },
    )?;
    let mut code = Vec::new();
    let mut sites = Vec::new();
    // Each placeholder is recorded at the instruction's address/displacement operand.
    macro_rules! emit {
        ($bytes:expr) => {
            code.extend_from_slice($bytes)
        };
    }
    macro_rules! operand {
        ($prefix:expr,$symbol:expr,$kind:expr) => {{
            emit!($prefix);
            let at = code.len();
            emit!(&[0; 4]);
            sites.push((at, $symbol, $kind));
        }};
    }
    if target == Target::X86 {
        // cmp dword [flag],1; jne failure. push type,caption,text,HWND; call IAT.
        operand!(
            &[0x83, 0x3d],
            FixupTarget::Symbol(flag.clone()),
            FixupKind::Va32
        );
        emit!(&[1, 0x75, 25]);
        emit!(&[0x6a, 0]);
        operand!(&[0xa1], FixupTarget::Symbol(pointer), FixupKind::Va32);
        emit!(&[0x50, 0x50, 0x6a, 0]);
        operand!(&[0xff, 0x15], FixupTarget::Import(message), FixupKind::Va32);
        emit!(&[0x6a, 0]);
        operand!(
            &[0xff, 0x15],
            FixupTarget::Import(exit.clone()),
            FixupKind::Va32
        );
        emit!(&[0x6a, 42]);
        operand!(&[0xff, 0x15], FixupTarget::Import(exit), FixupKind::Va32);
        emit!(&[0xcc]);
    } else {
        // sub rsp,40: 32 bytes shadow space plus alignment. This is the only prolog operation.
        emit!(&[0x48, 0x83, 0xec, 0x28]);
        let origin = code.len() as u32 + 7;
        operand!(
            &[0x83, 0x3d],
            FixupTarget::Symbol(flag.clone()),
            FixupKind::Rel32 { origin }
        );
        emit!(&[1, 0x75, 29]);
        emit!(&[0x31, 0xc9]);
        let origin = code.len() as u32 + 7;
        operand!(
            &[0x48, 0x8b, 0x15],
            FixupTarget::Symbol(pointer),
            FixupKind::Rel32 { origin }
        );
        emit!(&[0x49, 0x89, 0xd0, 0x45, 0x31, 0xc9]);
        let origin = code.len() as u32 + 6;
        operand!(
            &[0xff, 0x15],
            FixupTarget::Import(message),
            FixupKind::Rel32 { origin }
        );
        emit!(&[0x31, 0xc9]);
        let origin = code.len() as u32 + 6;
        operand!(
            &[0xff, 0x15],
            FixupTarget::Import(exit.clone()),
            FixupKind::Rel32 { origin }
        );
        emit!(&[0xb9, 42, 0, 0, 0]);
        let origin = code.len() as u32 + 6;
        operand!(
            &[0xff, 0x15],
            FixupTarget::Import(exit),
            FixupKind::Rel32 { origin }
        );
        emit!(&[0xcc]);
    }
    let entry_end = code.len() as u32;
    let callback = entry_end;
    if target == Target::X86 {
        // cmp [esp+8],DLL_PROCESS_ATTACH; jne return; mov dword [flag],1; ret 12.
        emit!(&[0x83, 0x7c, 0x24, 8, 1, 0x75, 10]);
        operand!(&[0xc7, 0x05], FixupTarget::Symbol(flag), FixupKind::Va32);
        emit!(&[1, 0, 0, 0, 0xc2, 12, 0]);
    } else {
        // cmp edx,DLL_PROCESS_ATTACH; jne return; mov dword [rip+flag],1; ret.
        emit!(&[0x83, 0xfa, 1, 0x75, 10]);
        let origin = code.len() as u32 + 10;
        operand!(
            &[0xc7, 0x05],
            FixupTarget::Symbol(flag),
            FixupKind::Rel32 { origin }
        );
        emit!(&[1, 0, 0, 0, 0xc3]);
    }
    let text = b.add_section(SectionSpec::new(".text", code, CODE))?;
    for (offset, target, kind) in sites {
        patch(&mut b, &text, offset, target, kind)?;
    }
    let entry = b.define_symbol(&text, 0)?;
    b.set_entry_point(&entry)?;
    let callback = b.define_symbol(&text, callback)?;
    let template = b.add_section(SectionSpec::new(".tls", vec![1, 2, 3, 4], WRITE))?;
    let start = b.define_symbol(&template, 0)?;
    let end = b.define_symbol(&template, 4)?;
    b.set_tls(TlsSpec {
        start,
        end,
        index,
        callbacks: if callback_enabled {
            vec![callback]
        } else {
            vec![]
        },
        zero_fill: 0,
        alignment: 4,
    })?;
    if target == Target::X64 {
        // UNWIND_INFO v1, 4-byte prolog, one UWOP_ALLOC_SMALL(40) at instruction offset 4.
        let unwind = b.add_section(SectionSpec::new(
            ".xdata",
            vec![1, 4, 1, 0, 4, 0x42, 0, 0],
            READ,
        ))?;
        let unwind = b.define_symbol(&unwind, 0)?;
        let end = b.define_symbol(&text, entry_end)?;
        b.add_runtime_function(&entry, &end, &unwind)?;
    }
    b.set_resources(hello_resources()?);
    b.build()
}
