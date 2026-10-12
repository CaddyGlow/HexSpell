#![cfg(all(feature = "pe", feature = "write"))]
use hexspell::pe::{
    build::{ImageKind, PeBuilder, SectionSpec, Target},
    certificate::{CertificateOwned, CertificateTableOwned},
    header::SECURITY,
    PE,
};
fn image(target: Target) -> PE {
    let mut b = PeBuilder::new(target, ImageKind::Executable);
    let text = b
        .add_section(SectionSpec::new(".text", vec![0xc3], 0x60000020))
        .unwrap();
    let entry = b.define_symbol(&text, 0).unwrap();
    b.set_entry_point(&entry).unwrap();
    b.build().unwrap()
}
#[test]
fn append_replace_remove_preserve_overlay_fields_and_unknown_records() {
    for target in [Target::X86, Target::X64] {
        let mut pe = image(target);
        pe.buffer.extend_from_slice(b"overlay!");
        let prefix = pe.buffer.clone();
        let unknown = CertificateOwned {
            revision: 0x1234,
            certificate_type: 0xabcd,
            data: vec![1, 2, 3],
            padding: vec![0x7a; 5],
        };
        let report = pe.append_certificate(&unknown).unwrap();
        let first = report.range.unwrap();
        assert!(first.start.is_multiple_of(8));
        assert_eq!(pe.optional_header.checksum.value, pe.calc_checksum());
        assert_eq!(
            pe.owned_certificates().unwrap().certificates,
            vec![unknown.clone()]
        );
        let first_bytes = pe.buffer[first.clone()].to_vec();
        pe.append_certificate(&CertificateOwned::pkcs_signed_data(vec![4; 17]))
            .unwrap();
        assert_eq!(&pe.buffer[first.clone()], first_bytes);
        assert_eq!(pe.certificates().unwrap().unwrap().certificates.len(), 2);
        let slot = &pe.optional_header.data_directories[SECURITY];
        for (i, byte) in prefix.iter().enumerate() {
            if (slot.virtual_address.offset..slot.size.offset + 4).contains(&i)
                || (pe.optional_header.checksum.offset..pe.optional_header.checksum.offset + 4)
                    .contains(&i)
            {
                continue;
            }
            assert_eq!(pe.buffer[i], *byte, "prefix byte {i}");
        }
        let owned = pe.owned_certificates().unwrap();
        assert_eq!(owned.serialize().unwrap(), pe.buffer[first.start..]);
        pe.replace_certificates(&CertificateTableOwned {
            certificates: vec![unknown],
        })
        .unwrap();
        let report = pe.remove_certificates().unwrap();
        assert_eq!(report.previous_range, Some(first.clone()));
        assert_eq!(report.range, None);
        assert_eq!(pe.buffer.len(), prefix.len());
        assert!(pe.certificates().unwrap().is_none());
        assert_eq!(pe.optional_header.checksum.value, pe.calc_checksum());
        pe.remove_certificates().unwrap();
    }
}
#[test]
fn serialization_recomputes_lengths_and_zeroes_resized_padding() {
    let table = CertificateTableOwned {
        certificates: vec![CertificateOwned {
            revision: 9,
            certificate_type: 10,
            data: vec![1; 2],
            padding: vec![0xff],
        }],
    };
    let bytes = table.serialize().unwrap();
    assert_eq!(&bytes[..8], &[10, 0, 0, 0, 9, 0, 10, 0]);
    assert_eq!(&bytes[10..], &[0; 6]);
}

#[test]
fn append_preserves_certificates_after_buffer_only_edits() {
    for target in [Target::X86, Target::X64] {
        for previously_signed in [false, true] {
            let mut pe = image(target);
            if previously_signed {
                pe.append_certificate(&CertificateOwned::pkcs_signed_data(vec![1; 16]))
                    .unwrap();
            }
            let mut edited = PE::from_buffer(pe.buffer.clone()).unwrap();
            edited
                .append_certificate(&CertificateOwned::pkcs_signed_data(vec![2; 17]))
                .unwrap();
            let mut expected = edited.owned_certificates().unwrap();
            pe.buffer = edited.buffer;
            let added = CertificateOwned::pkcs_signed_data(vec![3; 16]);
            expected.certificates.push(added.clone());

            pe.append_certificate(&added).unwrap();

            assert_eq!(pe.owned_certificates().unwrap(), expected);
        }
    }
}
#[test]
fn malformed_or_aliased_tables_are_rejected_without_mutation() {
    for target in [Target::X86, Target::X64] {
        for kind in 0..6 {
            let mut pe = image(target);
            pe.append_certificate(&CertificateOwned::pkcs_signed_data(vec![1; 16]))
                .unwrap();
            let table = pe.certificates().unwrap().unwrap();
            match kind {
                0 => pe.buffer.push(99), // post-certificate overlay must survive rejection
                1 => pe.optional_header.data_directories[SECURITY]
                    .size
                    .update(&mut pe.buffer, 0)
                    .unwrap(),
                2 => pe.sections[0]
                    .pointer_to_relocations
                    .update(&mut pe.buffer, table.offset as u32)
                    .unwrap(),
                3 => pe.sections[0]
                    .pointer_to_raw_data
                    .update(&mut pe.buffer, table.offset as u32)
                    .unwrap(),
                4 => pe
                    .coff_header
                    .size_of_optional_header
                    .update(&mut pe.buffer, 96)
                    .unwrap(),
                _ => pe.buffer[table.offset..table.offset + 4].copy_from_slice(&7u32.to_le_bytes()),
            }
            if kind == 2 {
                pe.sections[0]
                    .number_of_relocations
                    .update(&mut pe.buffer, 1)
                    .unwrap();
            }
            let before = pe.buffer.clone();
            assert!(pe.remove_certificates().is_err(), "kind {kind}");
            assert_eq!(pe.buffer, before);
        }
    }
}
#[test]
fn inconsistent_security_directory_is_not_treated_as_unsigned() {
    let mut pe = image(Target::X64);
    pe.optional_header.data_directories[SECURITY]
        .size
        .update(&mut pe.buffer, 8)
        .unwrap();
    assert!(pe.certificates().is_err());
    assert!(pe.owned_certificates().is_err());
}

#[test]
fn certificate_aliases_in_debug_and_coff_metadata_are_rejected() {
    for target in [Target::X86, Target::X64] {
        for debug_alias in [false, true] {
            let mut pe = image(target);
            pe.append_certificate(&CertificateOwned::pkcs_signed_data(vec![0; 16]))
                .unwrap();
            let offset = pe.certificates().unwrap().unwrap().offset as u32;
            if debug_alias {
                let raw = pe.sections[0].pointer_to_raw_data.value as usize;
                let rva = pe.sections[0].virtual_address.value;
                pe.buffer[raw..raw + 28].fill(0);
                pe.buffer[raw + 16..raw + 20].copy_from_slice(&8u32.to_le_bytes());
                pe.buffer[raw + 24..raw + 28].copy_from_slice(&offset.to_le_bytes());
                let debug = &mut pe.optional_header.data_directories[hexspell::pe::header::DEBUG];
                debug.virtual_address.update(&mut pe.buffer, rva).unwrap();
                debug.size.update(&mut pe.buffer, 28).unwrap();
            } else {
                pe.coff_header
                    .pointer_to_symbol_table
                    .update(&mut pe.buffer, offset)
                    .unwrap();
            }
            let before = pe.buffer.clone();
            assert!(pe.remove_certificates().is_err());
            assert!(pe
                .append_certificate(&CertificateOwned::pkcs_signed_data(vec![1]))
                .is_err());
            assert_eq!(pe.buffer, before);
        }
    }
}
