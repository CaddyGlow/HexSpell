//! Builds an unsigned dyld-linked library; run `codesign -s - OUTPUT` on macOS.
use hexspell::macho::build::*;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let target = match args.get(1).map(String::as_str) {
        Some("x86_64") => Target::X86_64,
        Some("arm64") => Target::Arm64,
        _ => return Err("usage: macho_dylib [x86_64|arm64] OUTPUT".into()),
    };
    let output = args.get(2).ok_or("missing output")?;
    let mut b = MachOBuilder::new_dylib(
        target,
        Version {
            major: 13,
            minor: 0,
            patch: 0,
        },
        "@rpath/libhexspell.dylib",
    )?;
    b.enable_dyld()?;
    let system = b.add_dependency("/usr/lib/libSystem.B.dylib")?;
    let text = b.add_segment(SegmentSpec::new("__TEXT", 5))?;
    let code = match target {
        Target::X86_64 => vec![0xb8, 42, 0, 0, 0, 0xc3, 0xff, 0x25, 0, 0, 0, 0],
        Target::Arm64 => [
            0x52800540u32,
            0xd65f03c0,
            0x90000010,
            0x91000210,
            0xf9400210,
            0xd61f0200,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect(),
    };
    let mut spec = SectionSpec::new("__text", code);
    spec.alignment = 2;
    let code = b.add_section(&text, spec)?;
    let answer = b.add_symbol("_answer", &code, 0)?;
    let data = b.add_segment(SegmentSpec::new("__DATA", 3))?;
    let mut spec = SectionSpec::new("__data", vec![0; 32]);
    spec.alignment = 3;
    spec.data[16..24].copy_from_slice(&0x12345678u64.to_le_bytes());
    let storage = b.add_section(&data, spec)?;
    b.add_fixup(&storage, 0, &answer, 0, FixupKind::Va64)?;
    b.add_symbol("_answer_pointer", &storage, 0)?;
    b.add_symbol("_initialized_marker", &storage, 16)?;
    b.add_import("_getpid", &system, &storage, 8)?;
    let pid = b.add_symbol("_getpid_slot", &storage, 8)?;
    let pid_offset = match target {
        Target::X86_64 => 6,
        Target::Arm64 => 8,
    };
    b.add_symbol("_imported_pid", &code, pid_offset)?;
    match target {
        Target::X86_64 => b.add_fixup(&code, 8, &pid, 0, FixupKind::Rel32 { origin: 12 })?,
        Target::Arm64 => {
            b.add_fixup(&code, 8, &pid, 0, FixupKind::Arm64Page21)?;
            b.add_fixup(&code, 12, &pid, 0, FixupKind::Arm64PageOffset12)?;
        }
    }
    add_runtime(&mut b, target, &text, &data, &system)?;
    let zero = b.add_section(&data, SectionSpec::zero_fill("__bss", 8))?;
    b.add_symbol("_zero_marker", &zero, 0)?;
    let custom = b.add_segment(SegmentSpec::new("__CUSTOM", 1))?;
    b.add_section(&custom, SectionSpec::new("__payload", vec![0; 64]))?;
    b.build()?.write_file(output)?;
    Ok(())
}

fn add_runtime(
    b: &mut MachOBuilder,
    target: Target,
    text: &SegmentId,
    data: &SegmentId,
    system: &DependencyId,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut marker = SectionSpec::new("__runtime", vec![0; 16]);
    marker.alignment = 3;
    let marker = b.add_section(data, marker)?;
    let init = b.add_symbol("_init_marker", &marker, 0)?;
    let callback = b.add_symbol("_fini_callback", &marker, 8)?;
    let mut constructors = Vec::new();
    let mut terminators = Vec::new();
    for (name, value, destructor) in [
        ("_init_one", 1u32, false),
        ("_init_two", 12, false),
        ("_fini_one", 1, true),
        ("_fini_two", 2, true),
    ] {
        let bytes = match (target, destructor) {
            (Target::X86_64, false) if value == 12 => vec![0x48, 0x83, 0x05, 0, 0, 0, 0, 11, 0xc3],
            (Target::X86_64, false) => {
                let mut v = vec![0x48, 0xc7, 0x05, 0, 0, 0, 0];
                v.extend(value.to_le_bytes());
                v.push(0xc3);
                v
            }
            (Target::Arm64, false) if value == 12 => [
                0x90000008u32,
                0x91000108,
                0xf9400109,
                0x91002d29,
                0xf9000109,
                0xd65f03c0,
            ]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
            (Target::Arm64, false) => [
                0x90000008,
                0x91000108,
                0xd2800009 | (value << 5),
                0xf9000109,
                0xd65f03c0,
            ]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
            (Target::X86_64, true) => {
                let mut v = vec![
                    0x48, 0x8b, 0x05, 0, 0, 0, 0, 0x48, 0x85, 0xc0, 0x74, 7, 0xbf,
                ];
                v.extend(value.to_le_bytes());
                v.extend([0xff, 0xe0, 0xc3]);
                v
            }
            (Target::Arm64, true) => [
                0x90000008,
                0x91000108,
                0xf9400108,
                0xb4000068,
                0xd2800000 | (value << 5),
                0xd61f0100,
                0xd65f03c0,
            ]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
        };
        let mut spec = SectionSpec::new(name, bytes);
        spec.alignment = 2;
        let section = b.add_section(text, spec)?;
        let symbol = b.add_symbol(name, &section, 0)?;
        let target_symbol = if destructor { &callback } else { &init };
        match (target, destructor) {
            (Target::X86_64, false) if value == 12 => b.add_fixup(
                &section,
                3,
                target_symbol,
                0,
                FixupKind::Rel32 { origin: 8 },
            )?,
            (Target::X86_64, false) => b.add_fixup(
                &section,
                3,
                target_symbol,
                0,
                FixupKind::Rel32 { origin: 11 },
            )?,
            (Target::X86_64, true) => b.add_fixup(
                &section,
                3,
                target_symbol,
                0,
                FixupKind::Rel32 { origin: 7 },
            )?,
            (Target::Arm64, false) => {
                b.add_fixup(&section, 0, target_symbol, 0, FixupKind::Arm64Page21)?;
                b.add_fixup(&section, 4, target_symbol, 0, FixupKind::Arm64PageOffset12)?;
            }
            (Target::Arm64, true) => {
                b.add_fixup(&section, 0, target_symbol, 0, FixupKind::Arm64Page21)?;
                b.add_fixup(&section, 4, target_symbol, 0, FixupKind::Arm64PageOffset12)?;
            }
        }
        if destructor {
            terminators.push(symbol);
        } else {
            constructors.push(symbol);
        }
    }
    b.add_initializers(data, &constructors)?;
    b.add_terminators(data, &terminators)?;
    let descriptor = b.add_thread_local(data, system, 0x11223344u64.to_le_bytes().to_vec(), 3)?;
    let descriptor = b.add_symbol("_tls_descriptor", &descriptor, 0)?;
    let bytes = match target {
        Target::X86_64 => vec![
            0x48, 0x83, 0xec, 8, 0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0xff, 0x17, 0x48, 0x83, 0xc4, 8,
            0xc3,
        ],
        Target::Arm64 => [
            0xa9bf7bfdu32,
            0x910003fd,
            0x90000000,
            0x91000000,
            0xf9400008,
            0xd63f0100,
            0xa8c17bfd,
            0xd65f03c0,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect(),
    };
    let mut spec = SectionSpec::new("__tls_code", bytes);
    spec.alignment = 2;
    let section = b.add_section(text, spec)?;
    b.add_symbol("_tls_address", &section, 0)?;
    match target {
        Target::X86_64 => {
            b.add_fixup(&section, 7, &descriptor, 0, FixupKind::Rel32 { origin: 11 })?
        }
        Target::Arm64 => {
            b.add_fixup(&section, 8, &descriptor, 0, FixupKind::Arm64Page21)?;
            b.add_fixup(&section, 12, &descriptor, 0, FixupKind::Arm64PageOffset12)?;
        }
    }
    let probe = match target {
        Target::X86_64 => vec![0x48, 0x83, 0xec, 8, 0xff, 0xd7, 0x48, 0x83, 0xc4, 8, 0xc3],
        Target::Arm64 => [0xa9bf7bf3u32, 0xd63f0000, 0xa8c17bf3, 0xd65f03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    };
    let length = probe.len();
    let mut spec = SectionSpec::new("__probe", probe);
    spec.alignment = 2;
    let probe = b.add_section(text, spec)?;
    let probe = b.add_symbol("_unwind_probe", &probe, 0)?;
    let (reg, cie_rules, fde_rules) = match target {
        Target::X86_64 => (16u8, vec![0x0c, 7, 8, 0x90, 1], vec![0x44, 0x0e, 16]),
        Target::Arm64 => (
            30u8,
            vec![0x0c, 31, 0],
            vec![0x44, 0x0e, 16, 0x93, 2, 0x9e, 1],
        ),
    };
    let mut cie = vec![0; 4];
    cie.extend([1, b'z', b'R', 0, 1, 0x78, reg, 1, 0x1b]);
    cie.extend(cie_rules);
    while cie.len() % 8 != 4 {
        cie.push(0);
    }
    let mut cfi = (cie.len() as u32).to_le_bytes().to_vec();
    cfi.extend(cie);
    let fde_start = cfi.len();
    let mut fde = ((fde_start + 4) as u32).to_le_bytes().to_vec();
    fde.extend([0; 4]);
    fde.extend((length as u32).to_le_bytes());
    fde.push(0);
    fde.extend(fde_rules);
    while fde.len() % 8 != 4 {
        fde.push(0);
    }
    cfi.extend((fde.len() as u32).to_le_bytes());
    cfi.extend(fde);
    cfi.extend([0; 4]);
    let cfi = b.add_unwind(text, cfi)?;
    b.add_fixup(&cfi, (fde_start + 8) as u64, &probe, 0, FixupKind::PcRel32)?;
    Ok(())
}
