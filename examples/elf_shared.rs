//! Build with `cargo run --features elf,write --example elf_shared -- /tmp/libhexspell.so`.
//! Load with `ctypes.CDLL` and call the exported `answer` function (returns 42).
use hexspell::elf::build::{
    Binding, ElfBuilder, FixupKind, ImageKind, SectionSpec, SegmentSpec, Target,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = ElfBuilder::new(Target::LinuxX86_64);
    builder.set_image_kind(ImageKind::SharedObject);
    builder.set_soname("libhexspell.so")?;
    let code = builder.add_segment(SegmentSpec::RX)?;
    let section = builder.add_section(
        Some(&code),
        SectionSpec::new(".text", vec![0xb8, 42, 0, 0, 0, 0xc3]),
    )?;
    let answer = builder.define_symbol("answer", &section, 0, 6, Binding::Global)?;
    builder.set_symbol_version(&answer, "HEXSPELL_1.0")?;
    let data_segment = builder.add_segment(SegmentSpec::RW)?;
    let pointer =
        builder.add_section(Some(&data_segment), SectionSpec::new(".data", vec![0; 8]))?;
    builder.define_symbol("answer_pointer", &pointer, 0, 8, Binding::Global)?;
    builder.add_fixup(&pointer, 0, &answer, FixupKind::Absolute64, 0)?;
    let initialized = builder.add_section(
        Some(&data_segment),
        SectionSpec::new(".marker", 0x1234_5678u64.to_le_bytes().to_vec()),
    )?;
    builder.define_symbol("initialized_marker", &initialized, 0, 8, Binding::Global)?;
    let zero = builder.add_section(Some(&data_segment), SectionSpec::zero_fill(".bss", 8, 8))?;
    builder.define_symbol("zero_marker", &zero, 0, 8, Binding::Global)?;
    let getpid = builder.add_versioned_import_slot("libc.so.6", "getpid", "GLIBC_2.2.5")?;
    let imported = builder.add_section(
        Some(&code),
        SectionSpec::new(".text.import", vec![0xff, 0x25, 0, 0, 0, 0]),
    )?;
    builder.define_symbol("imported_pid", &imported, 0, 6, Binding::Global)?;
    builder.add_fixup(&imported, 2, &getpid, FixupKind::PcRelative32, 0)?;
    let data_segment = builder.add_segment(SegmentSpec::RW)?;
    // Loader constructors and reverse-order finalizers.
    let marker = builder.add_section(
        Some(&data_segment),
        SectionSpec::new(".init_marker", vec![0; 8]),
    )?;
    let marker = builder.define_symbol("init_marker", &marker, 0, 8, Binding::Global)?;
    let callback = builder.add_section(
        Some(&data_segment),
        SectionSpec::new(".fini_callback", vec![0; 8]),
    )?;
    let callback = builder.define_symbol("fini_callback", &callback, 0, 8, Binding::Global)?;
    for n in 1..=2 {
        let section = builder.add_section(
            Some(&code),
            SectionSpec::new(
                ".text.init",
                vec![
                    0x48, 0x8b, 0x05, 0, 0, 0, 0, 0x48, 0x6b, 0xc0, 10, 0x48, 0x83, 0xc0, n, 0x48,
                    0x89, 0x05, 0, 0, 0, 0, 0xc3,
                ],
            ),
        )?;
        builder.add_fixup(&section, 3, &marker, FixupKind::PcRelative32, 0)?;
        builder.add_fixup(&section, 18, &marker, FixupKind::PcRelative32, 0)?;
        let function =
            builder.define_symbol(&format!("init_{n}"), &section, 0, 23, Binding::Global)?;
        builder.add_initializer(&function)?;
        let section = builder.add_section(
            Some(&code),
            SectionSpec::new(
                ".text.fini",
                vec![
                    0x48, 0x8b, 0x05, 0, 0, 0, 0, 0x48, 0x85, 0xc0, 0x74, 7, 0xbf, n, 0, 0, 0,
                    0xff, 0xe0, 0xc3,
                ],
            ),
        )?;
        builder.add_fixup(&section, 3, &callback, FixupKind::PcRelative32, 0)?;
        let function =
            builder.define_symbol(&format!("fini_{n}"), &section, 0, 20, Binding::Global)?;
        builder.add_finalizer(&function)?;
    }
    // General-dynamic TLS: each thread receives an independent copy.
    let template = builder.add_tls_template(0x11223344u64.to_le_bytes().to_vec(), 8)?;
    let tls = builder.add_tls_address_slot(&template, 0)?;
    let resolver = builder.add_import_slot("ld-linux-x86-64.so.2", "__tls_get_addr")?;
    let section = builder.add_section(
        Some(&code),
        SectionSpec::new(
            ".text.tls",
            vec![
                0x48, 0x83, 0xec, 8, 0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0xff, 0x15, 0, 0, 0, 0, 0x48,
                0x83, 0xc4, 8, 0xc3,
            ],
        ),
    )?;
    builder.add_fixup(&section, 7, &tls, FixupKind::PcRelative32, 0)?;
    builder.add_fixup(&section, 13, &resolver, FixupKind::PcRelative32, 0)?;
    builder.define_symbol("tls_address", &section, 0, 22, Binding::Global)?;
    // A caller-supplied CIE/FDE for a frame-pointer function calling its argument.
    let section = builder.add_section(
        Some(&code),
        SectionSpec::new(
            ".text.unwind",
            vec![0x55, 0x48, 0x89, 0xe5, 0xff, 0xd7, 0x5d, 0xc3],
        ),
    )?;
    let probe = builder.define_symbol("unwind_probe", &section, 0, 8, Binding::Global)?;
    let mut frame = vec![
        20, 0, 0, 0, 0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b, 0x0c, 7, 8, 0x90, 1, 0, 0,
    ];
    frame.extend_from_slice(&[
        28, 0, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0x41, 0x0e, 16, 0x86, 2, 0x43, 0x0d,
        6, 0x43, 0x0c, 7, 8, 0, 0, 0,
    ]);
    frame.extend_from_slice(&[0; 4]);
    builder.add_eh_frame(frame, &[(24, probe)])?;
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "libhexspell.so".into());
    if std::env::args().any(|arg| arg == "--stripped") {
        builder.emit_section_table(false);
    }
    std::fs::write(path, builder.build()?.buffer)?;
    Ok(())
}
