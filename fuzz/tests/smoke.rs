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
