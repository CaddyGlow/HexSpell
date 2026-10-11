//! Insertion regressions needed when editing generated images.
#![cfg(all(feature = "pe", feature = "common"))]

use hexspell::pe::{section::NewSection, PE};

#[path = "pefile/synthetic.rs"]
mod synthetic;

#[test]
fn insertion_covers_raw_extent_even_when_virtual_size_is_smaller() {
    for is64 in [false, true] {
        let mut pe = PE::from_buffer(synthetic::image(is64)).unwrap();
        let section = pe.sections.last_mut().unwrap();
        section.virtual_size.update(&mut pe.buffer, 1).unwrap();
        section
            .size_of_raw_data
            .update(&mut pe.buffer, 0x1800)
            .unwrap();
        pe.buffer.resize(0x1e00, 0);
        let old_rvas: Vec<_> = pe
            .sections
            .iter()
            .map(|s| s.virtual_address.value)
            .collect();
        let new = NewSection {
            name: ".new".into(),
            data: vec![0x77; 31],
            characteristics: 0x40000040,
        };
        let plan = hexspell::write::plan_pe_insert_section(&pe, &new).unwrap();
        pe.insert_section(new).unwrap();
        assert_eq!(pe.sections.last().unwrap().virtual_address.value, 0x5000);
        assert_eq!(plan.virtual_address, 0x5000);
        assert_eq!(
            plan.raw_data_offset,
            pe.sections.last().unwrap().pointer_to_raw_data.value
        );
        assert_eq!(plan.new_buffer_len, pe.buffer.len());
        assert_eq!(&pe.section_data(3).unwrap()[..31], &[0x77; 31]);
        assert_eq!(
            old_rvas,
            pe.sections[..3]
                .iter()
                .map(|s| s.virtual_address.value)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn insertion_uses_maximum_extents_and_retains_overlay() {
    for is64 in [false, true] {
        let mut bytes = synthetic::image(is64);
        bytes.extend_from_slice(b"overlay marker");
        let mut pe = PE::from_buffer(bytes).unwrap();
        // Permute virtual and physical positions, leaving table order unchanged.
        for (index, rva, raw) in [(0, 0x3000, 0x600), (2, 0x1000, 0x200)] {
            pe.sections[index]
                .virtual_address
                .update(&mut pe.buffer, rva)
                .unwrap();
            pe.sections[index]
                .pointer_to_raw_data
                .update(&mut pe.buffer, raw)
                .unwrap();
        }
        let new = NewSection {
            name: ".new".into(),
            data: vec![0x55; 0x200],
            characteristics: 0x40000040,
        };
        let plan = hexspell::write::plan_pe_insert_section(&pe, &new).unwrap();
        pe.insert_section(new).unwrap();
        assert_eq!(pe.sections.last().unwrap().virtual_address.value, 0x4000);
        assert_eq!(pe.sections.last().unwrap().pointer_to_raw_data.value, 0xa00);
        assert!(pe.buffer.ends_with(b"overlay marker"));
        assert_eq!(plan.new_buffer_len, pe.buffer.len());
        assert_eq!(plan.raw_data_offset, 0xa00);
    }
}

#[test]
fn invalid_insert_alignment_fails_before_mutation() {
    let mut pe = PE::from_buffer(synthetic::image(false)).unwrap();
    pe.optional_header
        .file_alignment
        .update(&mut pe.buffer, 0)
        .unwrap();
    let before = pe.buffer.clone();
    let new = NewSection {
        name: ".new".into(),
        data: vec![0],
        characteristics: 0x40000040,
    };
    assert!(hexspell::write::plan_pe_insert_section(&pe, &new).is_err());
    assert!(pe.insert_section(new).is_err());
    assert_eq!(pe.buffer, before);
}

#[test]
fn overflowing_insert_extent_is_rejected_by_plan_and_mutation() {
    let mut pe = PE::from_buffer(synthetic::image(true)).unwrap();
    pe.sections
        .last_mut()
        .unwrap()
        .virtual_size
        .update(&mut pe.buffer, 0xffffa000)
        .unwrap();
    let before = pe.buffer.clone();
    let new = NewSection {
        name: ".new".into(),
        data: vec![0; 0x4000],
        characteristics: 0x40000040,
    };
    assert!(hexspell::write::plan_pe_insert_section(&pe, &new).is_err());
    assert!(pe.insert_section(new).is_err());
    assert_eq!(pe.buffer, before);
}
