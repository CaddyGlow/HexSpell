#![cfg(all(feature = "std", feature = "pe", feature = "common"))]

use hexspell::pe::{self, header, import::ImportEntry, read::ImportEntryRef, PE};
use std::borrow::Cow;

#[test]
fn streaming_imports_match_owned_fields_names_and_thunks() {
    for path in [
        "tests/samples/sample1.exe",
        "tests/samples/sample64.exe",
        "tests/samples/sample2.dll",
    ] {
        let bytes = std::fs::read(path).unwrap();
        let pe = PE::from_slice(&bytes).unwrap();
        let owned = pe.imports().unwrap();
        let index = pe.rva_index();
        let streamed: Vec<_> = pe
            .imports_iter()
            .unwrap()
            .with_index(&index)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(streamed.len(), owned.dlls.len());
        for (dll, expected) in streamed.into_iter().zip(&owned.dlls) {
            assert_eq!(dll.dll_name, expected.dll_name);
            assert!(matches!(dll.dll_name, Cow::Borrowed(_)));
            assert_eq!(dll.descriptor.name.offset, expected.descriptor.name.offset);
            assert_eq!(dll.dll_name.as_ptr(), bytes[dll.dll_name_offset..].as_ptr());
            let entries: Vec<_> = dll.entries.collect::<Result<_, _>>().unwrap();
            assert_eq!(entries.len(), expected.entries.len());
            for (entry, expected) in entries.into_iter().zip(&expected.entries) {
                match (entry, expected) {
                    (
                        ImportEntryRef::ByName {
                            hint,
                            name_offset,
                            name,
                            thunk,
                        },
                        ImportEntry::ByName {
                            by_name,
                            thunk: expected,
                        },
                    ) => {
                        assert_eq!(hint.value, by_name.hint.value);
                        assert_eq!(hint.offset, by_name.hint.offset);
                        assert_eq!(name, by_name.name);
                        assert_eq!(name.as_ptr(), bytes[name_offset..].as_ptr());
                        assert_eq!(thunk.offset(), expected.offset());
                        assert_eq!(thunk.raw_value(), expected.raw_value());
                    }
                    (
                        ImportEntryRef::Ordinal { ordinal, thunk },
                        ImportEntry::Ordinal {
                            ordinal: expected,
                            thunk: expected_thunk,
                        },
                    ) => {
                        assert_eq!(ordinal, *expected);
                        assert_eq!(thunk.offset(), expected_thunk.offset());
                    }
                    _ => panic!("entry kinds differ"),
                }
            }
        }
        for (descriptor, dll) in owned.descriptors().zip(&owned.dlls) {
            assert!(std::ptr::eq(descriptor, &dll.descriptor));
        }
    }
}

#[test]
fn streaming_exports_match_named_ordinal_and_forwarder_rows() {
    let mut pe = PE::from_file("tests/samples/sample2.dll").unwrap();
    for forwarder in [false, true] {
        if forwarder {
            let exports = pe.exports().unwrap().unwrap();
            let mut field = exports.named[0].function_rva.clone();
            field
                .update(&mut pe.buffer, exports.named[0].name_rva.value)
                .unwrap();
        }
        let owned = pe.exports().unwrap().unwrap();
        let index = pe.rva_index();
        let names: Vec<_> = pe
            .exports_iter()
            .unwrap()
            .with_index(&index)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(names.len(), owned.named.len());
        for (entry, expected) in names.iter().zip(&owned.named) {
            assert_eq!(entry.name, expected.name);
            assert_eq!(entry.ordinal, expected.ordinal);
            assert_eq!(entry.name_rva.offset, expected.name_rva.offset);
            assert_eq!(
                entry.name_ordinal_index.offset,
                expected.name_ordinal_index.offset
            );
            assert_eq!(entry.function_rva.offset, expected.function_rva.offset);
        }
        let functions: Vec<_> = pe
            .export_functions_iter()
            .unwrap()
            .with_index(&index)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(functions.len(), owned.functions.len());
        for (entry, expected) in functions.iter().zip(&owned.functions) {
            match expected {
                pe::export::FunctionExport::Local {
                    ordinal,
                    index,
                    function_rva,
                } => {
                    assert_eq!(entry.ordinal, *ordinal);
                    assert_eq!(entry.index, *index);
                    assert_eq!(entry.function_rva.value, function_rva.value);
                    assert!(entry.forwarder.is_none());
                }
                pe::export::FunctionExport::Forwarder {
                    ordinal,
                    index,
                    function_rva,
                    forwarder,
                } => {
                    assert_eq!(entry.ordinal, *ordinal);
                    assert_eq!(entry.index, *index);
                    assert_eq!(entry.function_rva.offset, function_rva.offset);
                    assert_eq!(entry.forwarder, Some(forwarder.as_str()));
                }
            }
        }
    }
}

#[test]
fn relocation_parsing_is_lazy_and_edits_use_current_bytes() {
    let mut pe = PE::from_file("tests/samples/sample64.exe").unwrap();
    let owned = pe.base_relocations().unwrap();
    for (block, expected) in pe.base_relocations_iter().unwrap().zip(&owned) {
        let block = block.unwrap();
        assert_eq!(block.page_rva.offset, expected.page_rva.offset);
        let entries: Vec<_> = block.entries().collect();
        assert_eq!(entries.len(), expected.entries.len());
        for (entry, expected) in entries.iter().zip(&expected.entries) {
            assert_eq!(entry.raw.offset, expected.raw.offset);
            assert_eq!(entry.raw.value, expected.raw.value);
        }
    }
    let mut block_size = owned[0].block_size.clone();
    block_size.update(&mut pe.buffer, 7).unwrap();
    let mut pe = PE::from_buffer(pe.buffer).expect("headers must not parse relocations");
    assert!(pe.base_relocations().is_err());
    let mut blocks = pe.base_relocations_iter().unwrap();
    assert!(blocks.next().unwrap().is_err());
    assert!(blocks.next().is_none());
    let base_offset = pe.optional_header.image_base.offset;
    let old_base = pe.buffer[base_offset..base_offset + 8].to_vec();
    assert!(pe
        .apply_image_base(header::ImageBase::Base64(0x150000000))
        .is_err());
    assert_eq!(&pe.buffer[base_offset..base_offset + 8], old_base);
}

#[test]
fn directory_iterators_stop_after_errors_and_reject_hostile_counts() {
    let mut pe = PE::from_file("tests/samples/sample1.exe").unwrap();
    let descriptor = pe.imports().unwrap().dlls.remove(0).descriptor;
    let mut rva = descriptor.name;
    rva.update(&mut pe.buffer, u32::MAX).unwrap();
    let mut imports = pe.imports_iter().unwrap();
    assert!(imports.next().unwrap().is_err());
    assert!(imports.next().is_none());

    let mut pe = PE::from_file("tests/samples/sample2.dll").unwrap();
    let mut count = pe.exports().unwrap().unwrap().directory.number_of_names;
    count.update(&mut pe.buffer, u32::MAX).unwrap();
    assert!(pe.exports_iter().is_err());
    assert!(pe.exports().is_err());

    let mut bytes = vec![0; 32];
    bytes[4..8].copy_from_slice(&40u32.to_le_bytes());
    assert!(pe::read::Relocations::new(&bytes, 0, 16)
        .unwrap()
        .next()
        .unwrap()
        .is_err());
    assert!(pe::read::Relocations::new(&bytes, usize::MAX, 8).is_err());
    assert!(pe::read::DebugEntries::new(&bytes, 0, 29).is_err());
    assert!(pe::read::DebugEntries::new(&bytes, usize::MAX, 28).is_err());
    let debug = pe::debug::DebugDirectory::parse(&bytes, 0, 28).unwrap();
    let streamed = pe::read::DebugEntries::new(&bytes, 0, 28)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        streamed.pointer_to_raw_data.offset,
        debug.entries[0].pointer_to_raw_data.offset
    );
    assert_eq!(streamed.address_of_raw_data.offset, 20);
}

#[test]
fn rva_index_matches_linear_mapping_for_unsorted_overlapping_and_empty_ranges() {
    let mut pe = PE::from_file("tests/samples/sample1.exe").unwrap();
    for case in 0..6 {
        match case {
            1 => pe.sections.reverse(),
            2 => {
                pe.sections[1].virtual_address.value = pe.sections[0].virtual_address.value;
                pe.sections[1].size_of_raw_data.value = pe.sections[0].size_of_raw_data.value;
            }
            3 => pe.sections[0].size_of_raw_data.value = 0,
            4 => pe.sections[1].pointer_to_raw_data.value = u32::MAX,
            5 => pe.sections.clear(),
            _ => {}
        }
        let index = pe.rva_index();
        let mut rvas = vec![0, 1, 0x200, u32::MAX];
        for section in &pe.sections {
            let start = section.virtual_address.value;
            rvas.extend([
                start,
                start.saturating_sub(1),
                start.saturating_add(section.size_of_raw_data.value),
            ]);
            if section.size_of_raw_data.value > 0 {
                rvas.push(start.saturating_add(section.size_of_raw_data.value - 1));
            }
        }
        for rva in rvas {
            assert_eq!(
                index.rva_to_offset(rva).map_err(|e| e.to_string()),
                pe.rva_to_offset(rva).map_err(|e| e.to_string()),
                "case {case}, RVA {rva:x}"
            );
        }
    }
}

#[test]
fn missing_directories_yield_empty_iterators() {
    let mut pe = PE::from_file("tests/samples/sample1.exe").unwrap();
    for id in [
        header::IMPORT,
        header::EXPORT,
        header::DEBUG,
        header::BASERELOC,
    ] {
        pe.optional_header.data_directories[id]
            .virtual_address
            .value = 0;
        pe.optional_header.data_directories[id].size.value = 0;
    }
    assert_eq!(pe.imports_iter().unwrap().count(), 0);
    assert_eq!(pe.exports_iter().unwrap().count(), 0);
    assert_eq!(pe.export_functions_iter().unwrap().count(), 0);
    assert_eq!(pe.debug_iter().unwrap().count(), 0);
    assert_eq!(pe.base_relocations_iter().unwrap().count(), 0);
    assert!(pe.base_relocations().unwrap().is_empty());
}

#[test]
fn borrowed_directory_names_preserve_decoding_policy_and_index_identity() {
    let mut pe = PE::from_file("tests/samples/sample1.exe").unwrap();
    let name_offset = pe.imports().unwrap().dlls[0].dll_name_offset;
    pe.buffer[name_offset] = 0xff;
    let dll = pe.imports_iter().unwrap().next().unwrap().unwrap();
    assert!(matches!(dll.dll_name, Cow::Owned(_)));
    assert_eq!(dll.dll_name, pe.imports().unwrap().dlls[0].dll_name);
    let other = PE::from_buffer(pe.buffer.clone()).unwrap();
    let index = other.rva_index();
    assert!(pe.imports_iter().unwrap().with_index(&index).is_err());

    let mut pe = PE::from_file("tests/samples/sample2.dll").unwrap();
    let export = pe.exports().unwrap().unwrap().named.remove(0);
    let offset = pe.rva_to_offset(export.name_rva.value).unwrap();
    pe.buffer[offset] = 0xff;
    let mut exports = pe.exports_iter().unwrap();
    assert!(exports.next().unwrap().is_err());
    assert!(exports.next().is_none());
    assert!(pe.exports().is_err());
}
