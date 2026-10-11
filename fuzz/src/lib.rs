//! Executable fuzz harnesses shared by honggfuzz, tests, and replay.
use hexspell::{
    elf::{self, ELF},
    macho::{self, MachO},
    pe::{self, PE},
};

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
        assert_eq!(macho.buffer, owned.buffer);
        assert_eq!(macho.load_commands.len(), owned.load_commands.len());
        assert_eq!(macho.sections.len(), owned.sections.len());
        visit(macho.linked_dylibs_iter());
        let _ = macho.typed_commands();
        let _ = macho.symbols();
        let _ = macho.relocations();
        let _ = macho.exports();
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
        _ => return Err("target must be parse or roundtrip"),
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
