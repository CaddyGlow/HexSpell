#![cfg(all(feature = "pe", feature = "pe-reconstruct"))]

use hexspell::errors::FileParseError;
use hexspell::field::ByteOrder;
use hexspell::pe::{header, PE};

const NT: usize = 0x80;
const OPTIONAL: usize = NT + 24;

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    ByteOrder::Little.write_u32(bytes, offset, value);
}

fn table_offset(is64: bool) -> usize {
    OPTIONAL + if is64 { 240 } else { 224 }
}

fn directories(is64: bool) -> usize {
    OPTIONAL + if is64 { 112 } else { 96 }
}

// Independent synthetic mapped image. Original raw offsets deliberately differ
// from both RVAs and reconstructed file positions; no input file is needed.
fn memory_image(is64: bool) -> Vec<u8> {
    let mut bytes = vec![0; 0x4000];
    bytes[..2].copy_from_slice(b"MZ");
    put32(&mut bytes, 0x3c, NT as u32);
    bytes[NT..NT + 4].copy_from_slice(b"PE\0\0");
    let order = ByteOrder::Little;
    order.write_u16(&mut bytes, NT + 4, if is64 { 0x8664 } else { 0x14c });
    order.write_u16(&mut bytes, NT + 6, 4);
    order.write_u16(&mut bytes, NT + 20, if is64 { 240 } else { 224 });
    order.write_u16(&mut bytes, OPTIONAL, if is64 { 0x20b } else { 0x10b });
    put32(&mut bytes, OPTIONAL + 16, 0x1000);
    if is64 {
        order.write_u64(&mut bytes, OPTIONAL + 24, 0x140000000);
    } else {
        put32(&mut bytes, OPTIONAL + 28, 0x400000);
    }
    put32(&mut bytes, OPTIONAL + 32, 0x1000);
    put32(&mut bytes, OPTIONAL + 36, 0x200);
    put32(&mut bytes, OPTIONAL + 56, 0x4000);
    put32(&mut bytes, OPTIONAL + 60, 0x400);
    put32(&mut bytes, directories(is64) - 4, 16);
    for (i, (name, rva, virtual_size, raw_size, offset, flags)) in [
        (b".text\0\0\0", 0x1000, 0x180, 0x200, 0x600, 0x60000020),
        (b".data\0\0\0", 0x2000, 0x280, 0x200, 0x400, 0xc0000040),
        (b".bss\0\0\0\0", 0x3000, 0x100, 0, 0, 0xc0000080),
        (b".empty\0\0", 0, 0, 0, 0, 0x40000040),
    ]
    .into_iter()
    .enumerate()
    {
        let section = table_offset(is64) + i * 40;
        bytes[section..section + 8].copy_from_slice(name);
        put32(&mut bytes, section + 8, virtual_size);
        put32(&mut bytes, section + 12, rva);
        put32(&mut bytes, section + 16, raw_size);
        put32(&mut bytes, section + 20, offset);
        put32(&mut bytes, section + 36, flags);
        for j in 0..virtual_size {
            bytes[(rva + j) as usize] = (j.wrapping_add(i as u32 * 17) % 251) as u8;
        }
    }
    bytes
}

#[test]
fn reconstructs_pe32_and_pe64_with_file_aligned_sections() {
    for is64 in [false, true] {
        let memory = memory_image(is64);
        let before = memory.clone();
        let pe = PE::from_memory_image(&memory).unwrap();
        assert_eq!(memory, before);
        assert_eq!(pe.buffer.len(), 0xc00);
        assert_eq!(pe.optional_header.size_of_headers.value, 0x400);
        assert_eq!(pe.optional_header.size_of_image.value, 0x4000);
        assert_eq!(pe.optional_header.entry_point.value, 0x1000);
        assert_eq!(pe.optional_header.size_of_code.value, 0x200);
        assert_eq!(pe.optional_header.size_of_initialized_data.value, 0x600);
        assert_eq!(pe.optional_header.size_of_uninitialized_data.value, 0);
        for (i, (rva, length, offset, raw_size)) in [
            (0x1000, 0x180, 0x400, 0x200),
            (0x2000, 0x280, 0x600, 0x400),
            (0x3000, 0x100, 0xa00, 0x200),
        ]
        .into_iter()
        .enumerate()
        {
            let section = &pe.sections[i];
            assert_eq!(section.virtual_address.value, rva as u32);
            assert_eq!(section.pointer_to_raw_data.value, offset as u32);
            assert_eq!(section.size_of_raw_data.value, raw_size as u32);
            assert_eq!(pe.rva_to_offset(rva as u32).unwrap(), offset);
            let data = pe.section_data(i).unwrap();
            assert_eq!(&data[..length], &memory[rva..rva + length]);
            assert!(data[length..].iter().all(|byte| *byte == 0));
            let field_offset = table_offset(is64) + i * 40 + 20;
            assert_eq!(section.pointer_to_raw_data.offset, field_offset);
            assert_eq!(
                &pe.buffer[field_offset..field_offset + 4],
                &(offset as u32).to_le_bytes()
            );
        }
        assert!(pe.sections[2].has_initialized_data());
        assert!(!pe.sections[2].has_uninitialized_data());
        assert_eq!(pe.sections[3].pointer_to_raw_data.value, 0);
        assert_eq!(pe.sections[3].size_of_raw_data.value, 0);
        assert_eq!(pe.optional_header.checksum.value, pe.calc_checksum());
        let reparsed = PE::from_slice(&pe.buffer).unwrap();
        assert_eq!(reparsed.section_data(2).unwrap()[0], memory[0x3000]);
        // Section RVAs and all reconstructed bytes survive another mapping cycle.
        let mut remapped = vec![0; pe.optional_header.size_of_image.value as usize];
        remapped[..0x400].copy_from_slice(&pe.buffer[..0x400]);
        for (i, section) in pe.sections.iter().enumerate().take(3) {
            let rva = section.virtual_address.value as usize;
            let length = section.virtual_size.value as usize;
            remapped[rva..rva + length].copy_from_slice(&pe.section_data(i).unwrap()[..length]);
        }
        assert_eq!(PE::from_memory_image(&remapped).unwrap().buffer, pe.buffer);
    }
}

#[test]
fn zero_virtual_size_uses_original_raw_size() {
    let mut memory = memory_image(false);
    put32(&mut memory, table_offset(false) + 8, 0);
    memory[0x1180..0x1200].fill(0xab);
    let pe = PE::from_memory_image(&memory).unwrap();
    assert_eq!(pe.sections[0].virtual_size.value, 0);
    assert_eq!(&pe.section_data(0).unwrap()[0x180..], &[0xab; 0x80]);
}

#[test]
fn strips_file_only_metadata_without_following_stale_offsets() {
    for is64 in [false, true] {
        let mut memory = memory_image(is64);
        put32(&mut memory, NT + 12, u32::MAX);
        put32(&mut memory, NT + 16, 10);
        let security = directories(is64) + header::SECURITY * 8;
        put32(&mut memory, security, 0xfffffff0);
        put32(&mut memory, security + 4, 0x100);
        let table = table_offset(is64);
        put32(&mut memory, table + 24, u32::MAX);
        put32(&mut memory, table + 28, u32::MAX);
        ByteOrder::Little.write_u16(&mut memory, table + 32, 5);
        ByteOrder::Little.write_u16(&mut memory, table + 34, 6);
        let pe = PE::from_memory_image(&memory).unwrap();
        assert_eq!(pe.coff_header.pointer_to_symbol_table.value, 0);
        assert_eq!(pe.coff_header.number_of_symbols.value, 0);
        assert!(pe.certificates().unwrap().is_none());
        assert_eq!(
            pe.optional_header.data_directories[header::SECURITY]
                .size
                .value,
            0
        );
        assert_eq!(pe.sections[0].pointer_to_relocations.value, 0);
        assert_eq!(pe.sections[0].number_of_relocations.value, 0);
        assert_eq!(pe.sections[0].pointer_to_linenumbers.value, 0);
        assert_eq!(pe.sections[0].number_of_linenumbers.value, 0);
    }
}

fn debug_memory() -> Vec<u8> {
    let mut memory = memory_image(true);
    let directory = directories(true) + header::DEBUG * 8;
    put32(&mut memory, directory, 0x2000);
    put32(&mut memory, directory + 4, 56);
    memory[0x2000..0x2038].fill(0);
    put32(&mut memory, 0x200c, 2);
    put32(&mut memory, 0x2010, 16);
    put32(&mut memory, 0x2014, 0x2100);
    put32(&mut memory, 0x2018, 0xdeadbeef);
    // Second record's data only existed in the original file overlay.
    put32(&mut memory, 0x202c, 32);
    put32(&mut memory, 0x2034, 0xdeadbeef);
    memory
}

#[test]
fn remaps_debug_payloads_by_rva_and_clears_file_only_payloads() {
    let memory = debug_memory();
    let pe = PE::from_memory_image(&memory).unwrap();
    let debug = pe.debug_directory().unwrap().unwrap();
    assert_eq!(debug.entries[0].pointer_to_raw_data.value, 0x700);
    assert_eq!(debug.entries[0].address_of_raw_data.value, 0x2100);
    assert_eq!(
        debug.entries[0].raw_data(&pe.buffer).unwrap(),
        &memory[0x2100..0x2110]
    );
    assert_eq!(debug.entries[1].pointer_to_raw_data.value, 0);
    assert_eq!(debug.entries[1].size_of_data.value, 0);
}

#[test]
fn rejects_debug_ranges_that_are_not_fully_captured() {
    for (field, value) in [
        (0x2014, 0x2278),
        (0x2014, u32::MAX),
        (directories(true) + header::DEBUG * 8 + 4, 27),
        (directories(true) + header::DEBUG * 8, 0),
        (directories(true) + header::DEBUG * 8, 0x200),
    ] {
        let mut memory = debug_memory();
        put32(&mut memory, field, value);
        assert!(
            PE::from_memory_image(&memory).is_err(),
            "field={field:#x}, value={value:#x}"
        );
    }
}

#[test]
fn rejects_missing_headers_and_section_bytes() {
    let memory = memory_image(false);
    for end in [0, 0x3f, NT + 23, table_offset(false) + 159, 0x3ff, 0x30ff] {
        assert!(
            PE::from_memory_image(&memory[..end]).is_err(),
            "end={end:#x}"
        );
    }
}

#[test]
fn rejects_invalid_alignment_and_overlapping_virtual_sections() {
    for (field, value) in [
        (OPTIONAL + 36, 0),
        (OPTIONAL + 36, 513),
        (OPTIONAL + 36, 0x20000),
        (OPTIONAL + 32, 0),
        (OPTIONAL + 32, 0x800),
        (OPTIONAL + 60, 0x100),
        (table_offset(false) + 12, 0x100),
        (table_offset(false) + 12, 0x1001),
        (table_offset(false) + 40 + 12, 0x1000),
        (table_offset(false) + 8, 0x1100),
        (table_offset(false) + 8, u32::MAX),
        (table_offset(false) + 12, 0xfffff000),
    ] {
        let mut memory = memory_image(false);
        put32(&mut memory, field, value);
        assert!(
            PE::from_memory_image(&memory).is_err(),
            "field={field:#x}, value={value:#x}"
        );
    }
}

#[test]
fn does_not_treat_section_bytes_as_a_short_optional_header() {
    let mut memory = memory_image(false);
    ByteOrder::Little.write_u16(&mut memory, NT + 20, 96);
    assert!(matches!(
        PE::from_memory_image(&memory),
        Err(FileParseError::InvalidFileFormat)
    ));
}

#[test]
fn keeps_header_padding_and_realigns_size_of_headers() {
    let mut memory = memory_image(false);
    put32(&mut memory, OPTIONAL + 60, 0x380);
    memory[0x370..0x380].fill(0xab);
    let pe = PE::from_memory_image(&memory).unwrap();
    assert_eq!(pe.optional_header.size_of_headers.value, 0x400);
    assert_eq!(&pe.buffer[0x370..0x380], &[0xab; 16]);
    assert!(pe.buffer[0x380..0x400].iter().all(|byte| *byte == 0));
}

#[test]
fn reconstructs_existing_fixtures_and_preserves_lazy_directories() {
    for file in [
        include_bytes!("samples/sample1.exe").as_slice(),
        include_bytes!("samples/sample2.dll").as_slice(),
        include_bytes!("samples/sample64.exe").as_slice(),
    ] {
        let original = PE::from_slice(file).unwrap();
        let mut memory = vec![0; original.optional_header.size_of_image.value as usize];
        let header_size = original.optional_header.size_of_headers.value as usize;
        memory[..header_size].copy_from_slice(&file[..header_size]);
        for (i, section) in original.sections.iter().enumerate() {
            let raw = original.section_data(i).unwrap();
            let length = if section.virtual_size.value == 0 {
                raw.len()
            } else {
                raw.len().min(section.virtual_size.value as usize)
            };
            let start = section.virtual_address.value as usize;
            memory[start..start + length].copy_from_slice(&raw[..length]);
        }
        let rebuilt = PE::from_memory_image(&memory).unwrap();
        assert_eq!(
            rebuilt.coff_header.machine.value,
            original.coff_header.machine.value
        );
        assert_eq!(
            rebuilt.optional_header.entry_point.value,
            original.optional_header.entry_point.value
        );
        let import_names = |pe: &PE<&[u8]>| {
            pe.imports_iter()
                .unwrap()
                .map(|dll| dll.unwrap().dll_name.into_owned())
                .collect::<Vec<_>>()
        };
        let rebuilt_view = PE::from_slice(&rebuilt.buffer).unwrap();
        assert_eq!(import_names(&rebuilt_view), import_names(&original));
        let relocation_rvas = |pe: &PE<&[u8]>| {
            pe.base_relocations()
                .unwrap()
                .iter()
                .flat_map(|block| {
                    block
                        .entries
                        .iter()
                        .map(|entry| entry.rva(block.page_rva.value))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(relocation_rvas(&rebuilt_view), relocation_rvas(&original));
        let export_names = |pe: &PE<&[u8]>| {
            pe.exports_iter()
                .unwrap()
                .map(|entry| entry.unwrap().name.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(export_names(&rebuilt_view), export_names(&original));
    }
}

#[test]
fn section_table_order_need_not_match_rva_order() {
    let mut memory = memory_image(false);
    let table = table_offset(false);
    for byte in 0..40 {
        memory.swap(table + byte, table + 40 + byte);
    }
    let pe = PE::from_memory_image(&memory).unwrap();
    assert_eq!(pe.sections[0].name_str(), ".data");
    assert_eq!(pe.sections[0].pointer_to_raw_data.value, 0x400);
    assert_eq!(
        &pe.section_data(0).unwrap()[..0x280],
        &memory[0x2000..0x2280]
    );
    assert_eq!(pe.sections[1].name_str(), ".text");
    assert_eq!(pe.sections[1].pointer_to_raw_data.value, 0x800);
}

#[test]
fn accepts_header_only_images_with_no_data_directories() {
    let mut memory = memory_image(true);
    ByteOrder::Little.write_u16(&mut memory, NT + 6, 0);
    put32(&mut memory, directories(true) - 4, 0);
    memory.truncate(0x400);
    let pe = PE::from_memory_image(&memory).unwrap();
    assert!(pe.sections.is_empty());
    assert_eq!(pe.buffer.len(), 0x400);
    assert_eq!(pe.optional_header.size_of_image.value, 0x1000);
    assert_eq!(pe.optional_header.size_of_code.value, 0);
}
