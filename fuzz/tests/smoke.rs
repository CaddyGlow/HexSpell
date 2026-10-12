use hexspell_fuzz::{parse, roundtrip};
const SAMPLES: &[&[u8]] = &[
    include_bytes!("../../tests/samples/sample1.exe"),
    include_bytes!("../../tests/samples/sample64.exe"),
    include_bytes!("../../tests/samples/sample2.dll"),
    include_bytes!("../../tests/samples/linux"),
    include_bytes!("../../tests/samples/machO-OSX-x86-ls"),
];
#[test]
fn real_executables_cover_lazy_parsing_and_reversible_edits() {
    for bytes in SAMPLES {
        parse(bytes);
        roundtrip(bytes);
        hexspell_fuzz::signatures(bytes);
    }
}
#[test]
fn malformed_truncated_and_mutated_headers_do_not_panic() {
    for bytes in [&[][..], &[0xff; 512], &[0; 512]] {
        parse(bytes);
        roundtrip(bytes);
    }
    for bytes in SAMPLES {
        for length in [1, 16, 28, 32, 52, 64, 128, 256] {
            let prefix = &bytes[..length.min(bytes.len())];
            parse(prefix);
            roundtrip(prefix);
        }
        for offset in [4, 16, 20, 32, 60] {
            let mut mutated = bytes.to_vec();
            mutated[offset..offset + 4].fill(0xff);
            parse(&mutated);
            roundtrip(&mutated);
        }
    }
}
#[test]
fn oversized_inputs_and_unknown_targets_are_handled() {
    let bytes = vec![0; hexspell_fuzz::INPUT_LIMIT + 1];
    parse(&bytes);
    roundtrip(&bytes);
    assert!(hexspell_fuzz::run("unknown", &[]).is_err());
}

#[test]
fn synthetic_seeds_cover_word_sizes_byte_orders_and_fat_slices() {
    for (name, bytes) in hexspell_fuzz::synthetic_seeds() {
        if name.starts_with("elf") {
            assert!(hexspell::elf::ELF::from_slice(&bytes).is_ok(), "{name}");
        } else if name.starts_with("macho") {
            assert!(hexspell::macho::MachO::from_slice(&bytes).is_ok(), "{name}");
        } else {
            assert!(
                hexspell::macho::MachO::fat_slice_ref(&bytes, 0).is_ok(),
                "{name}"
            );
        }
        parse(&bytes);
        roundtrip(&bytes);
    }
}

#[test]
fn bounded_builders_and_editors_cover_payloads_and_alignments() {
    for selector in 0..=255u8 {
        let mut data = vec![selector; usize::from(selector)];
        if data.is_empty() {
            data.push(selector);
        }
        hexspell_fuzz::generation(&data);
    }
    hexspell_fuzz::generation(&[]);
    assert!(hexspell_fuzz::run("generation", &[1, 2, 3]).is_ok());
}

#[test]
fn signature_seeds_reach_readers_and_transactional_editors() {
    let seeds = hexspell_fuzz::signature_seeds();
    let mut names = std::collections::HashSet::new();
    for (name, bytes) in &seeds {
        assert!(names.insert(name.as_str()), "duplicate seed: {name}");
        assert!(bytes.len() <= hexspell_fuzz::INPUT_LIMIT, "{name}");
        parse(bytes);
        roundtrip(bytes);
        hexspell_fuzz::signatures(bytes);
        if name.ends_with("-records") {
            let pe = hexspell::pe::PE::from_buffer(bytes.clone()).unwrap();
            assert_eq!(
                pe.owned_certificates().unwrap().certificates.len(),
                2,
                "{name}"
            );
        }
        if name.ends_with("-signed") || name.contains("macho-read-") {
            let macho = hexspell::macho::MachO::from_buffer(bytes.clone()).unwrap();
            assert!(
                !macho.code_signature_data().unwrap().unwrap().is_empty(),
                "{name}"
            );
        }
        if name.ends_with("-entry-padding") {
            let mut macho = hexspell::macho::MachO::from_buffer(bytes.clone()).unwrap();
            assert!(macho.reserve_code_signature(32).is_err(), "{name}");
            assert_eq!(&macho.buffer, bytes);
        }
        if name.ends_with("-stacked") {
            let mut elf = hexspell::elf::ELF::from_buffer(bytes.clone()).unwrap();
            let outer = elf.appended_signature().unwrap().unwrap();
            assert_eq!(outer.data(&elf.buffer).unwrap(), b"outer");
            elf.set_appended_signature(b"outer").unwrap();
            assert_eq!(&elf.buffer, bytes);
            elf.remove_appended_signature().unwrap();
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
    for required in [
        "signature-pe32-records",
        "signature-pe64-records",
        "signature-macho-x64-entry-padding",
        "signature-macho-arm64-entry-padding",
        "signature-elf-1-1-stacked",
        "signature-elf-1-2-stacked",
        "signature-elf-2-1-stacked",
        "signature-elf-2-2-stacked",
    ] {
        assert!(names.contains(required), "missing {required}");
    }
    assert!(hexspell_fuzz::run("signatures", &[]).is_ok());
    hexspell_fuzz::signatures(&vec![0; hexspell_fuzz::INPUT_LIMIT + 1]);
}

#[test]
fn mutated_signature_seeds_preserve_transactional_rejection() {
    for (_, bytes) in hexspell_fuzz::signature_seeds() {
        for offset in [
            0,
            16,
            32,
            bytes.len().saturating_sub(40),
            bytes.len().saturating_sub(1),
        ] {
            if offset < bytes.len() {
                let mut mutated = bytes.clone();
                mutated[offset] ^= 0xff;
                hexspell_fuzz::signatures(&mutated);
            }
        }
        for length in [0, 16, 32, bytes.len().saturating_sub(1)] {
            hexspell_fuzz::signatures(&bytes[..length.min(bytes.len())]);
        }
    }
}
