//! Emits a dyld executable. Sign externally with `codesign -s - OUTPUT_PATH` before running.
use hexspell::macho::build::{FixupKind, MachOBuilder, SectionSpec, SegmentSpec, Target, Version};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let target = match args.next().as_deref() {
        Some("x86_64") => Target::X86_64,
        Some("arm64") => Target::Arm64,
        _ => return Err("usage: macho_hello [x86_64|arm64] OUTPUT_PATH".into()),
    };
    let output = args.next().ok_or("missing OUTPUT_PATH")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let mut b = MachOBuilder::new(
        target,
        Version {
            major: 13,
            minor: 0,
            patch: 0,
        },
    );
    b.enable_dyld()?;
    let system = b.add_dependency("/usr/lib/libSystem.B.dylib")?;
    let text = b.add_segment(SegmentSpec::new("__TEXT", 5))?;
    let bytes = match target {
        Target::X86_64 => vec![
            0x48, 0x83, 0xec, 8, 0xbf, 1, 0, 0, 0, 0x48, 0x8d, 0x35, 0, 0, 0, 0, 0xba, 15, 0, 0, 0,
            0xff, 0x15, 0, 0, 0, 0, 0x48, 0x83, 0xc4, 8, 0x31, 0xc0, 0xc3,
        ],
        Target::Arm64 => [
            0xa9bf7bfdu32,
            0x910003fd,
            0xd2800020,
            0x90000001,
            0x91000021,
            0xd28001e2,
            0x90000010,
            0x91000210,
            0xf9400210,
            0xd63f0200,
            0x52800000,
            0xa8c17bfd,
            0xd65f03c0,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect(),
    };
    let mut section = SectionSpec::new("__text", bytes);
    section.alignment = 2;
    let code = b.add_section(&text, section)?;
    let message = b.add_section(
        &text,
        SectionSpec::new("__cstring", b"Hello, Mach-O!\n".to_vec()),
    )?;
    let message = b.add_symbol("_message", &message, 0)?;
    let data = b.add_segment(SegmentSpec::new("__DATA", 3))?;
    let mut slots = SectionSpec::new("__got", vec![0; 8]);
    slots.alignment = 3;
    let slots = b.add_section(&data, slots)?;
    b.add_import("_write", &system, &slots, 0)?;
    let write = b.add_symbol("_write_slot", &slots, 0)?;
    match target {
        Target::X86_64 => {
            b.add_fixup(&code, 12, &message, 0, FixupKind::Rel32 { origin: 16 })?;
            b.add_fixup(&code, 23, &write, 0, FixupKind::Rel32 { origin: 27 })?;
        }
        Target::Arm64 => {
            b.add_fixup(&code, 12, &message, 0, FixupKind::Arm64Page21)?;
            b.add_fixup(&code, 16, &message, 0, FixupKind::Arm64PageOffset12)?;
            b.add_fixup(&code, 24, &write, 0, FixupKind::Arm64Page21)?;
            b.add_fixup(&code, 28, &write, 0, FixupKind::Arm64PageOffset12)?;
        }
    }
    b.set_entry(&code, 0)?;
    b.add_symbol("_main", &code, 0)?;
    let custom = b.add_segment(SegmentSpec::new("__CUSTOM", 1))?;
    b.add_section(&custom, SectionSpec::new("__payload", vec![0; 64]))?;
    b.build()?.write_file(&output)?;
    Ok(())
}
