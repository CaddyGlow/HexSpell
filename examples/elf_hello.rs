//! Run with `cargo run --features elf,write --example elf_hello -- /tmp/elf-hello`.
use hexspell::elf::build::{Binding, ElfBuilder, FixupKind, SectionSpec, SegmentSpec, Target};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = ElfBuilder::new(Target::LinuxX86_64);
    let code_segment = builder.add_segment(SegmentSpec::RX)?;
    let data_segment = builder.add_segment(SegmentSpec::R)?;
    // write(1, message, 12); exit(0), using RIP-relative addressing.
    let code = builder.add_section(
        Some(&code_segment),
        SectionSpec::new(
            ".text",
            vec![
                0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x48, 0x8d, 0x35, 0, 0, 0, 0, 0xba, 12, 0, 0,
                0, 0x0f, 0x05, 0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05,
            ],
        ),
    )?;
    let data = builder.add_section(
        Some(&data_segment),
        SectionSpec::new(".rodata", b"Hello, ELF!\n".to_vec()),
    )?;
    let message = builder.define_symbol("message", &data, 0, 12, Binding::Local)?;
    let entry = builder.define_symbol("_start", &code, 0, 33, Binding::Global)?;
    builder.set_entry(&entry)?;
    builder.add_fixup(&code, 13, &message, FixupKind::PcRelative32, 0)?;
    builder.add_section(None, SectionSpec::new(".custom", vec![0; 32]))?;
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "elf-hello".into());
    std::fs::write(&output, builder.build()?.buffer)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}
