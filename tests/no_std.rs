//! In-memory operations run against both the std and no_std library builds.
#[cfg(feature = "elf")]
use hexspell::elf::ELF;
#[cfg(feature = "macho")]
use hexspell::macho::MachO;
#[cfg(feature = "pe")]
use hexspell::pe::PE;
use hexspell::{
    errors::FileParseError,
    field::{ByteOrder, Field},
};

#[test]
#[cfg(feature = "pe")]
fn pe_fixtures_parse_and_edit_without_file_apis() {
    for bytes in [
        include_bytes!("samples/sample1.exe").as_slice(),
        include_bytes!("samples/sample64.exe").as_slice(),
    ] {
        let mut pe = PE::from_buffer(bytes.to_vec()).unwrap();
        assert!(!pe.sections.is_empty());
        assert!(!pe.imports().unwrap().dlls.is_empty());
        let entry = pe.optional_header.entry_point.value;
        pe.optional_header
            .entry_point
            .update(&mut pe.buffer, entry + 1)
            .unwrap();
        let parsed = PE::from_buffer(pe.buffer).unwrap();
        assert_eq!(parsed.optional_header.entry_point.value, entry + 1);
    }
}

#[test]
#[cfg(feature = "elf")]
fn elf_fixtures_parse_without_file_apis() {
    let elf = ELF::from_buffer(include_bytes!("samples/linux").to_vec()).unwrap();
    assert!(!elf.section_headers.is_empty());
}

#[test]
#[cfg(feature = "macho")]
fn macho_fixtures_parse_without_file_apis() {
    let macho = MachO::from_buffer(include_bytes!("samples/machO-OSX-x86-ls").to_vec()).unwrap();
    assert!(!macho.segments.is_empty());
    assert!(!macho.linked_dylibs().unwrap().is_empty());
}

#[test]
fn errors_and_fields_use_core_traits() {
    fn is_error<T: core::error::Error>() {}
    is_error::<FileParseError>();
    assert_eq!(
        FileParseError::BufferOverflow.to_string(),
        "Data out of bounds."
    );
    let mut bytes = [0; 4];
    let mut field = Field::new(0u32, 0, 4);
    field
        .update_with(&mut bytes, 0x12345678, ByteOrder::Little)
        .unwrap();
    assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);
}

#[test]
#[cfg(all(feature = "pe", feature = "write"))]
fn generated_images_use_only_in_memory_apis() {
    use hexspell::pe::{
        build::{ImageKind, PeBuilder, SectionSpec, Target},
        section::{CODE, EXECUTE, READ},
    };

    for target in [Target::X86, Target::X64] {
        let mut builder = PeBuilder::new(target, ImageKind::Executable);
        let text = builder
            .add_section(SectionSpec::new(".text", vec![0xc3], CODE | EXECUTE | READ))
            .unwrap();
        let entry = builder.define_symbol(&text, 0).unwrap();
        builder.set_entry_point(&entry).unwrap();
        let (image, report) = builder.build_with_layout().unwrap();
        assert_eq!(
            image.optional_header.entry_point.value,
            report.symbol(&entry).unwrap().rva
        );
        let reparsed = PE::from_slice(&image.buffer).unwrap();
        assert_eq!(reparsed.section_data(0).unwrap()[0], 0xc3);
        assert_eq!(builder.build().unwrap().buffer, image.buffer);
    }
}
