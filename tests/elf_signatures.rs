#![cfg(feature = "elf")]
use hexspell::{
    elf::signature::{AppendedSignature, MODULE_SIGNATURE_MARKER},
    field::ByteOrder,
};
fn trailer(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut bytes = payload.to_vec();
    bytes.extend_from_slice(signature);
    bytes.extend_from_slice(&[0, 0, 2, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    bytes.extend_from_slice(MODULE_SIGNATURE_MARKER);
    bytes
}
#[test]
fn reads_real_offsets_big_endian_length_and_exact_payloads() {
    let payload = b"unsigned prefix and overlay";
    let signature = vec![0xab; 0x102];
    let bytes = trailer(payload, &signature);
    let parsed = AppendedSignature::parse(&bytes).unwrap().unwrap();
    let info = payload.len() + signature.len();
    assert_eq!(parsed.signed_range, 0..payload.len());
    assert_eq!(parsed.signature_range, payload.len()..info);
    assert_eq!(parsed.algo.offset, info);
    assert_eq!(parsed.id_type.offset, info + 2);
    assert_eq!(parsed.padding.offset, info + 5);
    assert_eq!(parsed.padding.size, 3);
    assert_eq!(parsed.sig_len.offset, info + 8);
    assert_eq!(parsed.sig_len.size, 4);
    assert_eq!(parsed.sig_len.value, 0x102);
    assert_eq!(parsed.data(&bytes).unwrap(), signature);
    assert_eq!(parsed.signed_data(&bytes).unwrap(), payload);
    let mut changed = bytes.clone();
    let mut field = parsed.sig_len;
    field
        .update_with(&mut changed, 0x103, ByteOrder::Big)
        .unwrap();
    assert_eq!(&changed[info + 8..info + 12], &[0, 0, 1, 3]);
}
#[test]
fn rejects_truncated_and_malformed_marked_trailers() {
    assert!(AppendedSignature::parse(MODULE_SIGNATURE_MARKER).is_err());
    for len in 0..40 {
        let bytes = vec![0; len];
        assert!(AppendedSignature::parse(&bytes).unwrap().is_none());
    }
    let original = trailer(b"payload", b"signature");
    let info = original.len() - MODULE_SIGNATURE_MARKER.len() - 12;
    for index in 0..8 {
        let mut bytes = original.clone();
        bytes[info + index] = 0xff;
        assert!(AppendedSignature::parse(&bytes).is_err(), "index {index}");
    }
    for length in [0, 16, u32::MAX] {
        let mut bytes = original.clone();
        bytes[info + 8..info + 12].copy_from_slice(&length.to_be_bytes());
        assert!(AppendedSignature::parse(&bytes).is_err());
    }
    let mut extra = original.clone();
    extra.push(0);
    assert!(AppendedSignature::parse(&extra).unwrap().is_none());
    let parsed = AppendedSignature::parse(&original).unwrap().unwrap();
    assert!(parsed.data(&[]).is_err());
    assert!(parsed.signed_data(&[]).is_err());
}

#[cfg(feature = "write")]
mod editing {
    use super::*;
    use hexspell::elf::{
        build::layout::{serialize_layout, HeaderSpec, ProgramSpec, SectionHeaderSpec},
        header::ElfClass,
        section::{SHT_NOBITS, SHT_PROGBITS},
        ELF,
    };
    fn image(class: ElfClass, byte_order: ByteOrder, object: bool) -> ELF {
        let mut payload = vec![0; 128];
        payload[96..112].copy_from_slice(b"original payload");
        let programs = if object {
            vec![]
        } else {
            vec![ProgramSpec {
                kind: 1,
                offset: 96,
                file_size: 16,
                memory_size: 16,
                alignment: 1,
                ..Default::default()
            }]
        };
        serialize_layout(
            HeaderSpec {
                class,
                byte_order,
                os_abi: 0,
                image_type: if object { 1 } else { 2 },
                machine: if class == ElfClass::Elf32 { 3 } else { 62 },
                entry: 0,
                flags: 0,
                section_names: 0,
            },
            &payload,
            &programs,
            &[
                SectionHeaderSpec {
                    kind: SHT_PROGBITS,
                    offset: 96,
                    size: 16,
                    ..Default::default()
                },
                SectionHeaderSpec {
                    kind: SHT_NOBITS,
                    offset: u32::MAX as u64,
                    size: 1024,
                    ..Default::default()
                },
            ],
        )
        .unwrap()
    }
    #[test]
    fn set_replace_remove_preserves_all_original_bytes_in_all_elf_profiles() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for order in [ByteOrder::Little, ByteOrder::Big] {
                for object in [false, true] {
                    let mut elf = image(class, order, object);
                    elf.buffer.extend_from_slice(b"existing overlay");
                    let original = elf.buffer.clone();
                    let report = elf.set_appended_signature(&[0x5a; 258]).unwrap();
                    assert_eq!(report.signed_range, 0..original.len());
                    assert_eq!(report.previous_range, None);
                    assert_eq!(&elf.buffer[..original.len()], original);
                    let bytes = elf.buffer.clone();
                    let borrowed = ELF::from_slice(&bytes).unwrap();
                    assert_eq!(
                        borrowed
                            .appended_signature()
                            .unwrap()
                            .unwrap()
                            .sig_len
                            .value,
                        258
                    );
                    let parsed = elf.appended_signature().unwrap().unwrap();
                    assert_eq!(parsed.signed_data(&elf.buffer).unwrap(), original);
                    assert_eq!(
                        elf.buffer[parsed.sig_len.offset..parsed.sig_len.offset + 4],
                        [0, 0, 1, 2]
                    );
                    let replacement = elf.set_appended_signature(b"new").unwrap();
                    assert_eq!(replacement.previous_range, report.range);
                    assert_eq!(&elf.buffer[..original.len()], original);
                    assert_eq!(
                        elf.appended_signature()
                            .unwrap()
                            .unwrap()
                            .data(&elf.buffer)
                            .unwrap(),
                        b"new"
                    );
                    let removed = elf.remove_appended_signature().unwrap();
                    assert_eq!(removed.previous_range, replacement.range);
                    assert_eq!(removed.range, None);
                    assert_eq!(elf.buffer, original);
                    elf.remove_appended_signature().unwrap();
                    assert_eq!(elf.buffer, original);
                }
            }
        }
    }
    #[test]
    fn rejects_aliases_bad_lengths_and_empty_input_transactionally() {
        for kind in 0..6 {
            let mut elf = image(ElfClass::Elf64, ByteOrder::Little, false);
            let prefix = elf.buffer.len();
            elf.set_appended_signature(&[0; 32]).unwrap();
            let order = elf.byte_order().unwrap();
            match kind {
                0 => {
                    elf.section_headers[1]
                        .sh_offset_mut()
                        .update_with(&mut elf.buffer, prefix as u64, order)
                        .unwrap();
                }
                1 => {
                    elf.program_headers[0]
                        .p_offset_mut()
                        .update_with(&mut elf.buffer, prefix as u64, order)
                        .unwrap();
                }
                2 => {
                    let info = elf.appended_signature().unwrap().unwrap().sig_len.offset;
                    elf.buffer[info..info + 4].copy_from_slice(&u32::MAX.to_be_bytes());
                }
                3 => {
                    elf.header
                        .eh_size
                        .update_with(&mut elf.buffer, prefix as u16 + 1, order)
                        .unwrap();
                }
                4 => {
                    elf.header
                        .sh_off
                        .update_with(&mut elf.buffer, prefix as u64, order)
                        .unwrap();
                }
                _ => {}
            }
            let before = elf.buffer.clone();
            assert!(
                elf.set_appended_signature(if kind == 5 { &[] } else { b"signature" })
                    .is_err(),
                "kind {kind}"
            );
            if kind != 5 {
                assert!(elf.remove_appended_signature().is_err(), "kind {kind}");
            }
            assert_eq!(elf.buffer, before);
        }
    }
    #[test]
    fn removes_only_outermost_stacked_signature() {
        let mut elf = image(ElfClass::Elf64, ByteOrder::Little, true);
        elf.set_appended_signature(b"inner").unwrap();
        let inner = elf.buffer.clone();
        elf.buffer = trailer(&elf.buffer, b"outer");
        elf.remove_appended_signature().unwrap();
        assert_eq!(elf.buffer, inner);
        assert_eq!(
            elf.appended_signature()
                .unwrap()
                .unwrap()
                .data(&elf.buffer)
                .unwrap(),
            b"inner"
        );
    }
}
