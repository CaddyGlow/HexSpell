//! Executable fuzz harnesses shared by honggfuzz, tests, and replay.
use hexspell::{
    elf::{self, ELF},
    macho::{self, MachO},
    pe::{self, PE},
};

mod signatures;
pub use signatures::{signature_seeds, signatures};

/// Maximum file size accepted by a harness (1 MiB).
pub const INPUT_LIMIT: usize = 1 << 20;
/// Maximum streamed entries visited per table.
pub const ENTRY_LIMIT: usize = 4096;

fn visit<T, E>(items: impl Iterator<Item = Result<T, E>>) {
    for item in items.take(ENTRY_LIMIT) {
        if item.is_err() {
            break;
        }
    }
}

/// Parse arbitrary file bytes with header views, owned/borrowed parsers and lazy tables.
/// Parse errors are expected; panics and ownership inconsistencies are failures.
pub fn parse(data: &[u8]) {
    if data.len() > INPUT_LIMIT {
        return;
    }
    let _ = macho::dyld::decode_chained_fixups(data);
    let _ = elf::signature::AppendedSignature::parse(data);
    if let Ok(view) = pe::view::PeHeaders::parse(data) {
        let _ = view.magic();
        for i in 0..16 {
            let _ = view.directory_slot(i);
        }
        for i in 0..usize::from(view.coff.number_of_sections.value).min(ENTRY_LIMIT) {
            if view.section(i).is_err() {
                break;
            }
        }
        let _ = view.section(usize::MAX);
    }
    let borrowed = PE::from_slice(data);
    let owned = PE::from_buffer(data.to_vec());
    assert_eq!(borrowed.is_ok(), owned.is_ok());
    if let Ok(pe) = borrowed {
        let owned = owned.unwrap();
        assert_eq!(pe.buffer, owned.buffer);
        assert_eq!(pe.sections.len(), owned.sections.len());
        assert_eq!(
            pe.optional_header.entry_point.value,
            owned.optional_header.entry_point.value
        );
        let index = pe.rva_index();
        for bytes in data.as_chunks::<4>().0.iter().take(32) {
            let rva = u32::from_le_bytes(*bytes);
            assert_eq!(pe.rva_to_offset(rva).ok(), index.rva_to_offset(rva).ok());
        }
        if let Ok(items) = pe.imports_iter() {
            for dll in items.take(ENTRY_LIMIT) {
                match dll {
                    Ok(dll) => visit(dll.entries),
                    Err(_) => break,
                }
            }
        }
        if let Ok(items) = pe.imports_iter().and_then(|i| i.with_index(&index)) {
            for dll in items.take(ENTRY_LIMIT) {
                match dll {
                    Ok(dll) => visit(dll.entries),
                    Err(_) => break,
                }
            }
        }
        if let Ok(items) = pe.exports_iter() {
            visit(items);
        }
        if let Ok(items) = pe.export_functions_iter() {
            visit(items);
        }
        if let Ok(items) = pe.debug_iter() {
            visit(items);
        }
        if let Ok(items) = pe.base_relocations_iter() {
            for block in items.take(ENTRY_LIMIT) {
                match block {
                    Ok(block) => {
                        for entry in block.entries().take(ENTRY_LIMIT) {
                            std::hint::black_box(entry);
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        let _ = pe.imports();
        let _ = pe.exports();
        let _ = pe.base_relocations();
        let _ = pe.debug_directory();
        let _ = pe.tls();
        let _ = pe.exceptions();
        let _ = pe.bound_imports();
        let _ = pe.delay_imports();
        let _ = pe.load_config();
        let _ = pe.resources();
        let _ = pe.certificates();
        let _ = owned
            .owned_certificates()
            .and_then(|table| table.serialize());
        let _ = pe.clr();
        let _ = pe.coff_symbols();
        let _ = pe.rich_header();
        for i in 0..pe.sections.len() {
            let _ = pe.section_data(i);
        }
    }
    if let Ok(view) = elf::view::ElfHeaders::parse(data) {
        for i in 0..view.program_count().unwrap_or(0).min(ENTRY_LIMIT) {
            if view.program(i).is_err() {
                break;
            }
        }
        for i in 0..view.section_count().unwrap_or(0).min(ENTRY_LIMIT) {
            if view.section(i).is_err() {
                break;
            }
        }
        let _ = view.program(usize::MAX);
        let _ = view.section(usize::MAX);
    }
    let borrowed = ELF::from_slice(data);
    let owned = ELF::from_buffer(data.to_vec());
    assert_eq!(borrowed.is_ok(), owned.is_ok());
    if let Ok(elf) = borrowed {
        let owned = owned.unwrap();
        let _ = elf.appended_signature();
        if let Ok(Some(signature)) = elf.appended_signature() {
            let _ = signature.data(elf.buffer);
            let _ = signature.signed_data(elf.buffer);
        }
        assert_eq!(elf.buffer, owned.buffer);
        assert_eq!(elf.section_headers.len(), owned.section_headers.len());
        assert_eq!(elf.program_headers.len(), owned.program_headers.len());
        assert_eq!(elf.header.entry.value, owned.header.entry.value);
        for i in 0..elf.section_headers.len() {
            let _ = elf.section_name_ref(i);
            let _ = elf.section_data(i);
        }
        let _ = elf.symbols();
        let _ = elf.dynamic_symbols();
        let _ = elf.dynamic();
        let _ = elf.relocations();
        let _ = elf.sysv_hash();
        let _ = elf.gnu_hash();
        let _ = elf.version_symbols();
        let _ = elf.version_needs();
        let _ = elf.version_defs();
        let _ = elf.note_sections();
        let _ = elf.note_segments();
        let _ = elf.section_groups();
        let _ = elf.eh_frame_hdr();
        let _ = elf.init_array();
        let _ = elf.fini_array();
    }
    parse_macho(data);
    if let Ok(Some(fat)) = macho::fat::FatHeaders::parse(data) {
        let _ = fat.arch(usize::MAX);
        let _ = fat.slice(usize::MAX);
        for i in 0..fat.count.min(32) {
            let _ = fat.arch(i);
            if let Ok(slice) = fat.slice(i) {
                parse_macho(slice);
            }
        }
    }
    let _ = ELF::parse_archive(data);
}

fn parse_macho(data: &[u8]) {
    if let Ok(view) = macho::view::MachHeaders::parse(data) {
        visit(view.commands());
        let _ = view.command(usize::MAX);
    }
    let borrowed = MachO::from_slice(data);
    let owned = MachO::from_buffer(data.to_vec());
    assert_eq!(borrowed.is_ok(), owned.is_ok());
    if let Ok(macho) = borrowed {
        let owned = owned.unwrap();
        assert_eq!(
            macho.code_signature().is_ok(),
            owned.code_signature().is_ok()
        );
        assert_eq!(
            macho.code_signature_data().ok(),
            owned.code_signature_data().ok()
        );
        assert_eq!(macho.buffer, owned.buffer);
        assert_eq!(macho.load_commands.len(), owned.load_commands.len());
        assert_eq!(macho.sections.len(), owned.sections.len());
        visit(macho.linked_dylibs_iter());
        let _ = macho.typed_commands();
        let _ = macho.symbols();
        let _ = macho.relocations();
        let _ = macho.exports();
        let _ = macho.chained_fixup_slots();
        if let Ok(commands) = macho.typed_commands() {
            for command in commands {
                if let macho::load_command::TypedCommand::UnixThread(thread) = command {
                    let _ = thread.program_counter(macho.header.cpu_type.value, macho.byte_order());
                }
            }
        }
        for (lazy, weak) in [(false, false), (true, false), (false, true)] {
            let _ = macho.bind_opcodes(lazy, weak);
        }
    }
}

/// Patch a non-layout header field, reparse it, and restore the original bytes.
/// Values derive from the file tail so seeds are ordinary executable files.
pub fn roundtrip(data: &[u8]) {
    if data.len() > INPUT_LIMIT {
        return;
    }
    let value = data
        .iter()
        .rev()
        .take(4)
        .fold(0u32, |n, b| (n << 8) | u32::from(*b));
    if let Ok(mut pe) = PE::from_buffer(data.to_vec()) {
        let old = pe.coff_header.time_date_stamp.value;
        pe.coff_header
            .time_date_stamp
            .update(&mut pe.buffer, value)
            .unwrap();
        if let Ok(reparsed) = PE::from_slice(&pe.buffer) {
            assert_eq!(reparsed.coff_header.time_date_stamp.value, value);
        }
        pe.coff_header
            .time_date_stamp
            .update(&mut pe.buffer, old)
            .unwrap();
        assert_eq!(pe.buffer, data);
    }
    if let Ok(mut elf) = ELF::from_buffer(data.to_vec()) {
        let old = elf.header.flags.value;
        let order = elf.byte_order().unwrap();
        elf.header
            .flags
            .update_with(&mut elf.buffer, value, order)
            .unwrap();
        if let Ok(reparsed) = ELF::from_slice(&elf.buffer) {
            assert_eq!(reparsed.header.flags.value, value);
        }
        elf.header
            .flags
            .update_with(&mut elf.buffer, old, order)
            .unwrap();
        assert_eq!(elf.buffer, data);
    }
    if let Ok(mut macho) = MachO::from_buffer(data.to_vec()) {
        // FAT parsing selects a thin slice; preserve that selected buffer.
        let original = macho.buffer.clone();
        let old = macho.header.flags.value;
        let order = macho.byte_order();
        macho
            .header
            .flags
            .update_with(&mut macho.buffer, value, order)
            .unwrap();
        if let Ok(reparsed) = MachO::from_slice(&macho.buffer) {
            assert_eq!(reparsed.header.flags.value, value);
        }
        macho
            .header
            .flags
            .update_with(&mut macho.buffer, old, order)
            .unwrap();
        assert_eq!(macho.buffer, original);
    }
}

/// Dispatch a named harness, rejecting misspelled targets.
pub fn run(target: &str, data: &[u8]) -> Result<(), &'static str> {
    match target {
        "parse" => parse(data),
        "roundtrip" => roundtrip(data),
        "generation" => generation(data),
        "runtime-generation" => runtime_generation(data),
        "signatures" => signatures(data),
        _ => {
            return Err(
                "target must be parse, roundtrip, generation, runtime-generation or signatures",
            )
        }
    }
    Ok(())
}

/// Deterministic small seeds for both word sizes, byte orders, and FAT Mach-O.
pub fn synthetic_seeds() -> Vec<(String, Vec<u8>)> {
    use hexspell::field::ByteOrder;
    let mut seeds = Vec::new();
    for (endian, order) in [(1u8, ByteOrder::Little), (2, ByteOrder::Big)] {
        for class in [1u8, 2] {
            let mut elf = vec![0; if class == 1 { 52 } else { 64 }];
            elf[..4].copy_from_slice(b"\x7fELF");
            elf[4] = class;
            elf[5] = endian;
            elf[6] = 1;
            order.write_u32(&mut elf, 20, 1);
            let size = elf.len() as u16;
            order.write_u16(&mut elf, if class == 1 { 40 } else { 52 }, size);
            seeds.push((format!("elf-{class}-{endian}"), elf));
            let mut thin = vec![0; if class == 1 { 28 } else { 32 }];
            order.write_u32(
                &mut thin,
                0,
                if class == 1 { 0xfeedface } else { 0xfeedfacf },
            );
            order.write_u32(&mut thin, 4, 7);
            order.write_u32(&mut thin, 12, 1);
            let mut fat = vec![0; 28];
            ByteOrder::Big.write_u32(&mut fat, 0, 0xcafebabe);
            ByteOrder::Big.write_u32(&mut fat, 4, 1);
            ByteOrder::Big.write_u32(&mut fat, 8, 7);
            ByteOrder::Big.write_u32(&mut fat, 16, 28);
            ByteOrder::Big.write_u32(&mut fat, 20, thin.len() as u32);
            fat.extend_from_slice(&thin);
            seeds.push((format!("macho-{class}-{endian}"), thin));
            seeds.push((format!("fat-{class}-{endian}"), fat));
        }
    }
    seeds
}

/// Exercise bounded owned specifications and transactional payload edits.
/// Virtual extents and payload allocations are capped independently of input length.
pub fn generation(data: &[u8]) {
    use elf::build::{Binding, ElfBuilder, SectionSpec as ElfSection, SegmentSpec as ElfSegment};
    use macho::build::{
        MachOBuilder, SectionSpec as MachSection, SegmentSpec as MachSegment, Version,
    };
    if data.len() > INPUT_LIMIT {
        return;
    }
    runtime_generation(data);
    signatures::generation(data);
    let payload = &data[..data.len().min(256)];
    let selector = data.first().copied().unwrap_or(0);
    let mut elf = ElfBuilder::new(elf::build::Target::LinuxX86_64);
    let code = elf.add_segment(ElfSegment::RX).unwrap();
    let section = elf
        .add_section(Some(&code), ElfSection::new(".text", vec![0xc3]))
        .unwrap();
    let symbol = elf
        .define_symbol("_start", &section, 0, 1, Binding::Global)
        .unwrap();
    elf.set_entry(&symbol).unwrap();
    let mut spec = ElfSection::new(".custom", payload.to_vec());
    spec.alignment = 1 << (selector % 13);
    elf.add_section(None, spec).unwrap();
    let mut image = elf.build().unwrap();
    assert_eq!(image.buffer, elf.build().unwrap().buffer);
    parse(&image.buffer);
    let index = image
        .section_headers
        .iter()
        .enumerate()
        .find_map(|(i, _)| (image.section_name(i).ok().as_deref() == Some(".custom")).then_some(i))
        .unwrap();
    let before = image.buffer.clone();
    {
        let mut edit =
            elf::edit::ElfEdit::new(&mut image, elf::edit::BuildIdPolicy::Reject).unwrap();
        assert!(edit
            .replace_custom_section(index, &vec![0; payload.len() + 1])
            .is_err());
    }
    assert_eq!(before, image.buffer);
    let mut edit = elf::edit::ElfEdit::new(&mut image, elf::edit::BuildIdPolicy::Reject).unwrap();
    edit.replace_custom_section(index, &payload[..payload.len() / 2])
        .unwrap();
    edit.commit().unwrap();
    parse(&image.buffer);

    let target = if selector & 1 == 0 {
        macho::build::Target::X86_64
    } else {
        macho::build::Target::Arm64
    };
    let mut macho = MachOBuilder::new(
        target,
        Version {
            major: 13,
            minor: 0,
            patch: 0,
        },
    );
    let segment = macho.add_segment(MachSegment::new("__CUSTOM", 1)).unwrap();
    let mut spec = MachSection::new("__data", payload.to_vec());
    spec.alignment = u32::from(selector % 10);
    macho.add_section(&segment, spec).unwrap();
    let mut image = macho.build().unwrap();
    assert_eq!(image.buffer, macho.build().unwrap().buffer);
    parse(&image.buffer);
    let before = image.buffer.clone();
    {
        let mut edit = macho::edit::MachOEdit::new(&mut image).unwrap();
        assert!(edit
            .replace_custom_section(0, &vec![0; payload.len() + 1])
            .is_err());
    }
    assert_eq!(before, image.buffer);
    let mut edit = macho::edit::MachOEdit::new(&mut image).unwrap();
    edit.replace_custom_section(0, &payload[..payload.len() / 2])
        .unwrap();
    edit.commit().unwrap();
    parse(&image.buffer);
}

/// Bound runtime metadata and transactional growth independently of file fuzzing.
pub fn runtime_generation(data: &[u8]) {
    use elf::build::{Binding, ElfBuilder, ImageKind, SectionSpec, SegmentSpec, Target};
    let bytes = &data[..data.len().min(64)];
    let mut builder = ElfBuilder::new(Target::LinuxX86_64);
    builder.set_image_kind(ImageKind::SharedObject);
    let text = builder.add_segment(SegmentSpec::RX).unwrap();
    let section = builder
        .add_section(Some(&text), SectionSpec::new(".text", vec![0xc3]))
        .unwrap();
    let function = builder
        .define_symbol("function", &section, 0, 1, Binding::Global)
        .unwrap();
    builder.add_initializer(&function).unwrap();
    builder.add_finalizer(&function).unwrap();
    let tls = builder
        .add_tls_template(vec![0; bytes.len().max(1)], 8)
        .unwrap();
    builder.add_tls_address_slot(&tls, 0).unwrap();
    builder
        .add_section(None, SectionSpec::new(".custom", bytes.to_vec()))
        .unwrap();
    let mut image = builder.build().unwrap();
    assert_eq!(image.buffer, builder.build().unwrap().buffer);
    parse(&image.buffer);
    let index = (0..image.section_headers.len())
        .find(|&i| image.section_name(i).ok().as_deref() == Some(".custom"))
        .unwrap();
    let mut edit = elf::edit::ElfEdit::new(&mut image, elf::edit::BuildIdPolicy::Reject).unwrap();
    edit.grow_custom_section(index, &vec![0x55; bytes.len() + 8])
        .unwrap();
    edit.add_custom_section(".new", bytes).unwrap();
    edit.commit().unwrap();
    parse(&image.buffer);
    let unsigned = image.buffer.clone();
    image
        .set_appended_signature(if bytes.is_empty() { &[0] } else { bytes })
        .unwrap();
    let signature = image.appended_signature().unwrap().unwrap();
    assert_eq!(signature.signed_data(&image.buffer).unwrap(), unsigned);
    parse(&image.buffer);
    image.remove_appended_signature().unwrap();
    assert_eq!(image.buffer, unsigned);

    use macho::build::{
        FixupKind, MachOBuilder, SectionSpec as MachSection, SegmentSpec as MachSegment, Version,
    };
    let target = if data.first().copied().unwrap_or(0) & 1 == 0 {
        macho::build::Target::X86_64
    } else {
        macho::build::Target::Arm64
    };
    let mut builder = MachOBuilder::new(
        target,
        Version {
            major: 13,
            minor: 0,
            patch: 0,
        },
    );
    builder.enable_dyld().unwrap();
    let text = builder.add_segment(MachSegment::new("__TEXT", 5)).unwrap();
    let mut spec = MachSection::new("__text", vec![0xc0, 0x03, 0x5f, 0xd6]);
    spec.alignment = 2;
    let code = builder.add_section(&text, spec).unwrap();
    builder.set_entry(&code, 0).unwrap();
    let function = builder.add_symbol("_function", &code, 0).unwrap();
    let segment = builder.add_segment(MachSegment::new("__DATA", 3)).unwrap();
    let dependency = builder
        .add_dependency("/usr/lib/libSystem.B.dylib")
        .unwrap();
    let mut spec = MachSection::new("__pointers", vec![0; 16]);
    spec.alignment = 3;
    let pointers = builder.add_section(&segment, spec).unwrap();
    builder
        .add_import("_getpid", &dependency, &pointers, 0)
        .unwrap();
    builder
        .add_fixup(&pointers, 8, &function, 0, FixupKind::Va64)
        .unwrap();
    builder
        .add_initializers(&segment, core::slice::from_ref(&function))
        .unwrap();
    builder
        .add_terminators(&segment, core::slice::from_ref(&function))
        .unwrap();
    builder
        .add_thread_local(&segment, &dependency, vec![0; bytes.len().max(1)], 3)
        .unwrap();
    let image = builder.build().unwrap();
    assert_eq!(image.buffer, builder.build().unwrap().buffer);
    assert!(image.chained_fixups().unwrap().is_some());
    parse(&image.buffer);
}
