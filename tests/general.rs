#![cfg(all(
    feature = "std",
    feature = "pe",
    feature = "elf",
    feature = "macho",
    feature = "common"
))]

/// General tests for shared utilities
/// ==================================
/// Verifies common functionality such as `Field` updates and error
/// propagation that apply across binary formats.
use hexspell::errors::FileParseError;
use hexspell::field::{ByteOrder, Field, FixedBytes};
use hexspell::pe;

// Support function
fn load_section_name_field() -> (Vec<u8>, Field<FixedBytes<8>>) {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Cannot open the PE");
    let buffer_clone = pe.buffer.clone();
    let field = pe.sections[0].name.clone();
    (buffer_clone, field)
}

#[test]
fn byte_order_reads_reject_overflowing_offsets() {
    for order in [ByteOrder::Little, ByteOrder::Big] {
        assert!(matches!(
            order.read_u16(&[], usize::MAX),
            Err(FileParseError::BufferOverflow)
        ));
        assert!(matches!(
            order.read_u32(&[], usize::MAX),
            Err(FileParseError::BufferOverflow)
        ));
        assert!(matches!(
            order.read_u64(&[], usize::MAX),
            Err(FileParseError::BufferOverflow)
        ));
    }
}

#[test]
fn test_field_u32_value_bounds() {
    let mut buffer = [0u8; 3];
    let mut field = Field::new(0u32, 0, 3);
    field.update(&mut buffer, 0x00ABCDEFu32).unwrap();
    assert_eq!(
        &buffer,
        &0x00ABCDEFu32.to_le_bytes()[..3],
        "u32 bytes were not written correctly",
    );

    let err = field.update(&mut buffer, 0x01000000u32).unwrap_err();
    assert!(matches!(err, FileParseError::ValueTooLarge));
}

#[test]
fn test_field_u16_value_bounds() {
    let mut buffer = [0u8; 1];
    let mut field = Field::new(0u16, 0, 1);
    field.update(&mut buffer, 0x7Fu16).unwrap();
    assert_eq!(buffer[0], 0x7Fu8, "u16 byte was not written correctly");

    let err = field.update(&mut buffer, 0x1FFu16).unwrap_err();
    assert!(matches!(err, FileParseError::ValueTooLarge));
}

#[test]
fn test_field_u64_value_bounds() {
    let mut buffer = [0u8; 7];
    let mut field = Field::new(0u64, 0, 7);
    field.update(&mut buffer, 0x00DEADBEEFCAFEu64).unwrap();
    assert_eq!(
        &buffer,
        &0x00DEADBEEFCAFEu64.to_le_bytes()[..7],
        "u64 bytes were not written correctly",
    );

    let err = field
        .update(&mut buffer, 0x0100000000000000u64)
        .unwrap_err();
    assert!(matches!(err, FileParseError::ValueTooLarge));
}

#[test]
fn test_field_u32_update_big_endian() {
    let mut buffer = [0u8; 4];
    let mut field = Field::new(0u32, 0, 4);
    field
        .update_with(&mut buffer, 0x12345678, ByteOrder::Big)
        .unwrap();
    assert_eq!(buffer, [0x12, 0x34, 0x56, 0x78]);
}

#[test]
fn test_field_u64_update_big_endian_truncated() {
    let mut buffer = [0u8; 4];
    let mut field = Field::new(0u64, 0, 4);
    field
        .update_with(&mut buffer, 0xAABBCCDDu64, ByteOrder::Big)
        .unwrap();
    assert_eq!(buffer, [0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn test_overflow_error_value_unchanged() {
    let (mut buffer, mut name_field) = load_section_name_field();
    let original_value = name_field.value;
    let size = name_field.size;
    let overflow = "A".repeat(size + 1);

    let err = name_field
        .update_str(&mut buffer, overflow.as_str())
        .expect_err("Expected a BufferOverflow error");

    assert!(matches!(err, FileParseError::BufferOverflow));
    assert_eq!(
        name_field.value, original_value,
        "Field value must not change on error"
    );
}

#[test]
fn test_padding_shorter() {
    let (mut buffer, mut name_field) = load_section_name_field();
    let new_name = ".t";
    let offset = name_field.offset;
    let size = name_field.size;

    name_field.update_str(&mut buffer, new_name).unwrap();

    assert_eq!(
        &buffer[offset..offset + new_name.len()],
        new_name.as_bytes()
    );

    assert!(
        buffer[offset + new_name.len()..offset + size]
            .iter()
            .all(|&b| b == 0),
        "Remaining bytes were not zero-padded"
    );
}

#[test]
fn test_exact_fit() {
    let (mut buffer, mut name_field) = load_section_name_field();
    let size = name_field.size;
    let exact = "X".repeat(size);
    let offset = name_field.offset;

    name_field.update_str(&mut buffer, exact.as_str()).unwrap();

    assert_eq!(
        &buffer[offset..offset + size],
        exact.as_bytes(),
        "Exact-fit write failed"
    );
}

#[test]
fn test_overflow_error() {
    let (mut buffer, mut name_field) = load_section_name_field();
    let size = name_field.size;
    let overflow = "A".repeat(size + 1);

    let err = name_field
        .update_str(&mut buffer, overflow.as_str())
        .expect_err("Expected a BufferOverflow error");

    assert!(
        matches!(err, FileParseError::BufferOverflow),
        "Expected BufferOverflow, got {:?}",
        err
    );
}

#[test]
fn test_utf8_multibyte() {
    let (mut buffer, mut name_field) = load_section_name_field();
    let new_name = "ñáç";
    let bytes = new_name.as_bytes();
    let size = name_field.size;
    let offset = name_field.offset;

    assert!(
        bytes.len() <= size,
        "UTF-8 byte length ({}) exceeds field size ({})",
        bytes.len(),
        size
    );

    name_field.update_str(&mut buffer, new_name).unwrap();

    assert_eq!(
        &buffer[offset..offset + bytes.len()],
        bytes,
        "UTF-8 bytes were not written correctly"
    );

    assert!(
        buffer[offset + bytes.len()..offset + size]
            .iter()
            .all(|&b| b == 0),
        "Remaining bytes were not zero-padded after UTF-8 write"
    );
}

#[test]
fn field_accessor_metadata_and_big_endian_updates() {
    use hexspell::field::{ByteOrder, Field, FieldMut, NumericFieldMut};
    let mut buffer = [0xa5; 16];
    let mut short = Field::new(7u16, 2, 2);
    let mut accessor = FieldMut::<u16>::new(&mut short);
    assert_eq!(
        (accessor.value(), accessor.offset(), accessor.size()),
        (7, 2, 2)
    );
    accessor
        .update_with(&mut buffer, 0x1234, ByteOrder::Big)
        .unwrap();
    assert_eq!(&buffer[2..4], &[0x12, 0x34]);
    let mut word = Field::new(8u32, 4, 4);
    let accessor = FieldMut::<u32>::new(&mut word);
    assert_eq!(
        (accessor.value(), accessor.offset(), accessor.size()),
        (8, 4, 4)
    );
    let numeric = NumericFieldMut::U32(&mut word);
    assert_eq!(
        (numeric.value(), numeric.offset(), numeric.size()),
        (8, 4, 4)
    );
    let mut wide = Field::new(9u64, 8, 8);
    let mut numeric = NumericFieldMut::U64(&mut wide);
    assert_eq!(
        (numeric.value(), numeric.offset(), numeric.size()),
        (9, 8, 8)
    );
    numeric
        .update_with(&mut buffer, 0x123456789abcdef0, ByteOrder::Big)
        .unwrap();
    assert_eq!(
        &buffer[8..],
        &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]
    );
    assert_eq!(&buffer[..2], &[0xa5; 2]);
}

#[test]
fn promoted_numeric_fields_reject_overflow_without_mutation() {
    use hexspell::errors::FileParseError;
    use hexspell::field::{ByteOrder, Field};
    for order in [ByteOrder::Little, ByteOrder::Big] {
        let mut buffer = [0xa5; 8];
        let mut short = Field::new(0u16, 1, 1);
        short.update_with(&mut buffer, 0x12, order).unwrap();
        let before = buffer;
        assert!(matches!(
            short.update_with(&mut buffer, 0x100, order),
            Err(FileParseError::ValueTooLarge)
        ));
        assert_eq!(short.value, 0x12);
        assert_eq!(buffer, before);
        let mut word = Field::new(0u32, 1, 2);
        word.update_with(&mut buffer, 0x1234, order).unwrap();
        let before = buffer;
        assert!(matches!(
            word.update_with(&mut buffer, 0x10000, order),
            Err(FileParseError::ValueTooLarge)
        ));
        assert_eq!(word.value, 0x1234);
        assert_eq!(buffer, before);
        let mut wide = Field::new(0u64, 1, 4);
        wide.update_with(&mut buffer, 0x12345678, order).unwrap();
        let before = buffer;
        assert!(matches!(
            wide.update_with(&mut buffer, 1 << 32, order),
            Err(FileParseError::ValueTooLarge)
        ));
        assert_eq!(wide.value, 0x12345678);
        assert_eq!(buffer, before);
    }
}

#[test]
fn error_messages_and_io_sources_preserve_context() {
    use hexspell::errors::FileParseError;
    use std::error::Error;
    for (error, expected) in [
        (FileParseError::InvalidFileFormat, "Invalid file format."),
        (FileParseError::BufferOverflow, "Data out of bounds."),
        (FileParseError::ValueTooLarge, "Value exceeds field size."),
        (
            FileParseError::UnsupportedFeature("compression".into()),
            "Unsupported feature: compression",
        ),
    ] {
        assert_eq!(error.to_string(), expected);
        assert!(error.source().is_none());
    }
    let error = FileParseError::from(std::io::Error::other("read failed"));
    assert_eq!(error.to_string(), "I/O error: read failed");
    assert_eq!(error.source().unwrap().to_string(), "read failed");
}
