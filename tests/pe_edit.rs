#![cfg(all(feature = "std", feature = "pe", feature = "common"))]

use hexspell::pe::{header::PEType, load_config::LoadConfigDirectory, PE};

#[path = "pefile/synthetic.rs"]
mod synthetic;

#[test]
fn pe32_load_config_preserves_affinity_and_cookie_layout() {
    let mut buffer = vec![0; 64];
    buffer[..4].copy_from_slice(&64u32.to_le_bytes());
    buffer[48..52].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    buffer[52..54].copy_from_slice(&0x1122u16.to_le_bytes());
    buffer[54..56].copy_from_slice(&0x3344u16.to_le_bytes());
    buffer[56..60].copy_from_slice(&0x5566_7788u32.to_le_bytes());
    buffer[60..64].copy_from_slice(&0x99aa_bbccu32.to_le_bytes());
    let mut config = LoadConfigDirectory::parse(&buffer, 0, PEType::PE32).unwrap();
    let affinity = config.process_affinity_mask.as_ref().unwrap();
    assert_eq!(
        (affinity.value, affinity.offset, affinity.size),
        (0x1234_5678, 48, 4)
    );
    assert_eq!(
        (config.csd_version.value, config.csd_version.offset),
        (0x1122, 52)
    );
    assert_eq!(
        (config.reserved1.value, config.reserved1.offset),
        (0x3344, 54)
    );
    assert_eq!(
        (config.reserved2.value, config.reserved2.offset),
        (0x5566_7788, 56)
    );
    assert_eq!(
        (
            config.security_cookie.value,
            config.security_cookie.offset,
            config.security_cookie.size
        ),
        (0x99aa_bbcc, 60, 4)
    );
    config.security_cookie.update(&mut buffer, 0x1234).unwrap();
    assert_eq!(&buffer[56..60], &0x5566_7788u32.to_le_bytes());
}

#[test]
fn checksum_adds_full_file_length_after_folding() {
    // pefile's independent checksum for this existing PE64 fixture is 167333.
    let pe = PE::from_buffer(include_bytes!("samples/sample64.exe").to_vec()).unwrap();
    assert_eq!(pe.calc_checksum(), 167333);
    assert!(pe.calc_checksum() as usize >= pe.buffer.len());
}

#[test]
fn remove_sections_preserves_remaining_raw_payloads() {
    for is_64 in [false, true] {
        for index in 0..3 {
            let mut pe = PE::from_buffer(synthetic::image(is_64)).unwrap();
            let mut expected: Vec<Vec<u8>> = (0..3)
                .map(|index| pe.section_data(index).unwrap().to_vec())
                .collect();
            expected.remove(index);
            pe.remove_section(index).unwrap();
            for (index, bytes) in expected.iter().enumerate() {
                assert_eq!(pe.section_data(index).unwrap(), bytes);
                assert_eq!(pe.sections[index].pointer_to_raw_data.value % 512, 0);
            }
        }
    }
}

#[test]
fn optional_header_growth_preserves_raw_alignment_and_payloads() {
    for is_64 in [false, true] {
        for extra in [16, 512, 1024] {
            let mut pe = PE::from_buffer(synthetic::image(is_64)).unwrap();
            let expected: Vec<Vec<u8>> = (0..3)
                .map(|index| pe.section_data(index).unwrap().to_vec())
                .collect();
            pe.grow_optional_header(extra).unwrap();
            for (index, bytes) in expected.iter().enumerate() {
                assert_eq!(pe.section_data(index).unwrap(), bytes);
                assert_eq!(pe.sections[index].pointer_to_raw_data.value % 512, 0);
            }
        }
    }
}

#[test]
fn insert_remove_and_header_growth_preserve_overlay_and_file_pointers() {
    use hexspell::pe::{
        header::{DEBUG, SECURITY},
        section::{NewSection, READ},
    };
    for is_64 in [false, true] {
        let mut pe = PE::from_buffer(synthetic::image(is_64)).unwrap();
        // A valid COFF symbol and string table followed by a certificate overlay.
        let symbols = pe.buffer.len();
        pe.buffer.extend_from_slice(&[0; 18]);
        pe.buffer.extend_from_slice(&4u32.to_le_bytes());
        pe.coff_header
            .pointer_to_symbol_table
            .update(&mut pe.buffer, symbols as u32)
            .unwrap();
        pe.coff_header
            .number_of_symbols
            .update(&mut pe.buffer, 1)
            .unwrap();
        while !pe.buffer.len().is_multiple_of(8) {
            pe.buffer.push(0);
        }
        let certificate = pe.buffer.len();
        pe.buffer.extend_from_slice(&16u32.to_le_bytes());
        pe.buffer.extend_from_slice(&0x200u16.to_le_bytes());
        pe.buffer.extend_from_slice(&2u16.to_le_bytes());
        pe.buffer.extend_from_slice(b"OVERLAY!");
        pe.optional_header.data_directories[SECURITY]
            .virtual_address
            .update(&mut pe.buffer, certificate as u32)
            .unwrap();
        pe.optional_header.data_directories[SECURITY]
            .size
            .update(&mut pe.buffer, 16)
            .unwrap();
        let raw = pe.sections[1].pointer_to_raw_data.value as usize;
        let rva = pe.sections[1].virtual_address.value;
        pe.buffer[raw..raw + 28].fill(0);
        pe.buffer[raw + 16..raw + 20].copy_from_slice(&4u32.to_le_bytes());
        pe.buffer[raw + 20..raw + 24].copy_from_slice(&(rva + 128).to_le_bytes());
        pe.buffer[raw + 24..raw + 28].copy_from_slice(&((raw + 128) as u32).to_le_bytes());
        pe.buffer[raw + 128..raw + 132].copy_from_slice(b"DBUG");
        pe.optional_header.data_directories[DEBUG]
            .virtual_address
            .update(&mut pe.buffer, rva)
            .unwrap();
        pe.optional_header.data_directories[DEBUG]
            .size
            .update(&mut pe.buffer, 28)
            .unwrap();
        let overlay = pe.buffer[symbols..].to_vec();
        for operation in 0..3 {
            match operation {
                0 => {
                    pe.insert_section(NewSection {
                        name: ".added".into(),
                        data: vec![0x5a; 513],
                        characteristics: READ,
                    })
                    .unwrap();
                }
                1 => pe.remove_section(pe.sections.len() - 1).unwrap(),
                _ => pe.grow_optional_header(16).unwrap(),
            }
            assert!(pe.buffer.ends_with(&overlay));
            assert_eq!(pe.coff_symbols().unwrap().symbols.len(), 1);
            assert_eq!(
                pe.certificates().unwrap().unwrap().certificates[0]
                    .data(&pe.buffer)
                    .unwrap(),
                b"OVERLAY!"
            );
            let debug = pe.debug_directory().unwrap().unwrap();
            assert_eq!(debug.entries[0].raw_data(&pe.buffer).unwrap(), b"DBUG");
        }
    }
}

#[test]
fn chpe_metadata_pointer_uses_sdk_offset_width_and_va() {
    use hexspell::pe::{
        arch_data::{ArchitectureDataKind, HybridLoadConfigFields, IMAGE_FILE_MACHINE_ARM64},
        header::LOAD_CONFIG,
    };
    for is_64 in [false, true] {
        let kind = if is_64 {
            PEType::PE32Plus
        } else {
            PEType::PE32
        };
        let (relative, width) = if is_64 { (200, 8) } else { (124, 4) };
        let mut pe = PE::from_buffer(synthetic::image(is_64)).unwrap();
        pe.coff_header
            .machine
            .update(&mut pe.buffer, IMAGE_FILE_MACHINE_ARM64)
            .unwrap();
        let load = pe.sections[1].pointer_to_raw_data.value as usize;
        let metadata = pe.sections[2].pointer_to_raw_data.value as usize;
        pe.buffer[load..load + 320].fill(0);
        pe.buffer[load..load + 4].copy_from_slice(&320u32.to_le_bytes());
        let base = if is_64 { 0x1_4000_0000u64 } else { 0x40_0000 };
        let pointer = base + pe.sections[2].virtual_address.value as u64;
        pe.buffer[load + relative..load + relative + width]
            .copy_from_slice(&pointer.to_le_bytes()[..width]);
        pe.buffer[metadata..metadata + 12].copy_from_slice(
            &[
                1u32.to_le_bytes(),
                0x1234u32.to_le_bytes(),
                0x5678u32.to_le_bytes(),
            ]
            .concat(),
        );
        pe.optional_header.data_directories[LOAD_CONFIG]
            .virtual_address
            .update(&mut pe.buffer, pe.sections[1].virtual_address.value)
            .unwrap();
        pe.optional_header.data_directories[LOAD_CONFIG]
            .size
            .update(&mut pe.buffer, 320)
            .unwrap();
        let fields = HybridLoadConfigFields::parse(
            &pe.buffer,
            load,
            (relative + width) as u32,
            IMAGE_FILE_MACHINE_ARM64,
            kind,
        )
        .unwrap();
        let field = fields.hybrid_metadata_pointer.unwrap();
        assert_eq!(
            (field.offset, field.size, field.value),
            (load + relative, width, pointer)
        );
        let architecture = pe.architecture_data().unwrap();
        assert_eq!(architecture.kind, ArchitectureDataKind::ChpeMetadata);
        assert_eq!(architecture.offset, metadata);
        assert_eq!(architecture.code_map_rva.unwrap().value, 0x1234);
        assert_eq!(architecture.code_map_size.unwrap().value, 0x5678);
    }
}
