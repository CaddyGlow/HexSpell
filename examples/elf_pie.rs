//! Linux x86-64 PIE using an eager libc `write` import slot.
//! `cargo run --features elf,write --example elf_pie -- /tmp/elf-pie [--stripped]`
use hexspell::elf::build::{
    Binding, ElfBuilder, FixupKind, ImageKind, SectionSpec, SegmentSpec, Target,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = ElfBuilder::new(Target::LinuxX86_64);
    builder.set_image_kind(ImageKind::Pie);
    builder.set_interpreter("/lib64/ld-linux-x86-64.so.2")?;
    let rx = builder.add_segment(SegmentSpec::RX)?;
    let ro = builder.add_segment(SegmentSpec::R)?;
    let code = builder.add_section(
        Some(&rx),
        SectionSpec::new(
            ".text",
            vec![
                0xbf, 1, 0, 0, 0, 0x48, 0x8d, 0x35, 0, 0, 0, 0, 0xba, 12, 0, 0, 0, 0xff, 0x15, 0,
                0, 0, 0, 0x31, 0xff, 0xb8, 60, 0, 0, 0, 0x0f, 0x05,
            ],
        ),
    )?;
    let data = builder.add_section(
        Some(&ro),
        SectionSpec::new(".rodata", b"Hello, ELF!\n".to_vec()),
    )?;
    let message = builder.define_symbol("message", &data, 0, 12, Binding::Local)?;
    let entry = builder.define_symbol("_start", &code, 0, 32, Binding::Global)?;
    let write_slot = builder.add_import_slot("libc.so.6", "write")?;
    builder.add_fixup(&code, 8, &message, FixupKind::PcRelative32, 0)?;
    builder.add_fixup(&code, 19, &write_slot, FixupKind::PcRelative32, 0)?;
    builder.set_entry(&entry)?;
    let mut args = std::env::args().skip(1);
    let output = args.next().unwrap_or_else(|| "elf-pie".into());
    builder.emit_section_table(args.next().as_deref() != Some("--stripped"));
    std::fs::write(&output, builder.build()?.buffer)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}
