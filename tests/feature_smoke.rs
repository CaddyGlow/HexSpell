//! This target intentionally compiles with every independent feature combination.
#[test]
fn core_fields_are_always_available() {
    let mut bytes = [0u8; 4];
    let mut field = hexspell::field::Field::new(0u32, 0, 4);
    field.update(&mut bytes, 42).unwrap();
    assert_eq!(bytes, 42u32.to_le_bytes());
}
#[cfg(feature = "pe")]
#[test]
fn pe_parser_is_available() {
    assert!(hexspell::pe::PE::from_buffer(vec![]).is_err());
}
#[cfg(feature = "elf")]
#[test]
fn elf_parser_is_available() {
    assert!(hexspell::elf::ELF::from_buffer(vec![]).is_err());
}
#[cfg(feature = "macho")]
#[test]
fn macho_parser_is_available() {
    assert!(hexspell::macho::MachO::from_buffer(vec![]).is_err());
}
#[cfg(feature = "common")]
#[test]
fn common_helpers_work_without_formats() {
    assert_eq!(
        hexspell::strings::read_c_string(b"hello\0", 0).unwrap(),
        "hello"
    );
    assert!(hexspell::validation::find_overlaps(&[]).is_empty());
    assert!(hexspell::write::WriteMode::DryRun.is_dry_run());
}
