#![cfg(all(feature = "macho", feature = "write"))]
use hexspell::macho::build::*;
fn builder(target: Target) -> MachOBuilder {
    MachOBuilder::new(
        target,
        Version {
            major: 13,
            minor: 0,
            patch: 0,
        },
    )
}
#[test]
fn structural_profiles_symbols_and_zero_fill() {
    for target in [Target::X86_64, Target::Arm64] {
        let mut b = builder(target);
        let text = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
        let code = b
            .add_section(&text, SectionSpec::new("__text", vec![0xc3]))
            .unwrap();
        b.set_entry(&code, 0).unwrap();
        let sym = b.add_symbol("_main", &code, 0).unwrap();
        let data = b.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
        b.add_section(&data, SectionSpec::zero_fill("__bss", 0x1000))
            .unwrap();
        let (image, layout) = b.build_with_layout().unwrap();
        assert_eq!(&image.buffer[..4], &[0xcf, 0xfa, 0xed, 0xfe]);
        assert_eq!(
            u32::from_le_bytes(image.buffer[16..20].try_into().unwrap()),
            6
        );
        assert_eq!(layout.sections[0].file_offset, Some(480));
        assert_eq!(layout.entry_file_offset, Some(480));
        assert_eq!(layout.sections[1].file_offset, None);
        assert_eq!(layout.sections[1].size, 0x1000);
        assert_eq!(
            b.symbol_address(&sym, &layout).unwrap(),
            layout.sections[0].virtual_address
        );
        assert_eq!(image.buffer[480], 0xc3);
        assert_eq!(image.sections.len(), 2);
        let symbols = image.symbols().unwrap().unwrap();
        assert_eq!(symbols.symbols[0].name, "_main");
        assert_eq!(
            symbols.symbols[0].n_value.value,
            layout.sections[0].virtual_address
        );
        assert_eq!(symbols.symbols[0].n_sect.value, 1);
        assert_eq!(b.build().unwrap().buffer, image.buffer);
    }
}
#[test]
fn rejects_foreign_handles_and_invalid_layouts_without_mutation() {
    let mut a = builder(Target::X86_64);
    let mut b = builder(Target::X86_64);
    let foreign = a.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    assert!(b
        .add_section(&foreign, SectionSpec::new("__text", vec![1]))
        .is_err());
    assert!(b
        .add_segment(SegmentSpec::new("abcdefghijklmnopq", 1))
        .is_err());
    assert!(b.add_segment(SegmentSpec::new("__WX", 7)).is_err());
    assert!(b.add_segment(SegmentSpec::new("__PAGEZERO", 0)).is_err());
    let data = b.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
    let zero = b
        .add_section(&data, SectionSpec::zero_fill("__bss", u64::MAX))
        .unwrap();
    assert!(b.set_entry(&zero, 0).is_err());
    assert!(b.build().is_err());
    assert!(b.build().is_err());
}
#[test]
fn zero_fill_cannot_be_followed_by_initialized_storage() {
    let mut b = builder(Target::X86_64);
    let s = b.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
    b.add_section(&s, SectionSpec::zero_fill("__bss", 8))
        .unwrap();
    b.add_section(&s, SectionSpec::new("__data", vec![1]))
        .unwrap();
    assert!(b.build().is_err());
}
#[test]
fn alignment_and_stale_layout_are_rejected() {
    let mut b = builder(Target::X86_64);
    let s = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let mut invalid = SectionSpec::new("__bad", vec![1]);
    invalid.alignment = 13;
    assert!(b.add_section(&s, invalid).is_err());
    let code = b
        .add_section(&s, SectionSpec::new("__text", vec![0xc3]))
        .unwrap();
    let symbol = b.add_symbol("_main", &code, 0).unwrap();
    let (_, layout) = b.build_with_layout().unwrap();
    b.set_entry(&code, 0).unwrap();
    assert!(b.symbol_address(&symbol, &layout).is_err());
    let data = b.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
    let mut aligned = SectionSpec::new("__data", vec![1]);
    aligned.alignment = 12;
    b.add_section(&data, aligned).unwrap();
    let (_, layout) = b.build_with_layout().unwrap();
    assert_eq!(layout.sections[1].virtual_address % 4096, 0);
    assert_eq!(layout.sections[1].file_offset.unwrap() % 4096, 0);
}
#[test]
fn x86_relative_and_absolute_fixups_are_checked() {
    let mut b = builder(Target::X86_64);
    let s = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let code = b
        .add_section(&s, SectionSpec::new("__text", vec![0; 16]))
        .unwrap();
    let target = b.add_symbol("_target", &code, 7).unwrap();
    b.add_fixup(&code, 0, &target, 0, FixupKind::Rel32 { origin: 4 })
        .unwrap();
    b.add_fixup(&code, 8, &target, 0, FixupKind::Va64).unwrap();
    assert!(b.add_fixup(&code, 3, &target, 0, FixupKind::Va64).is_err());
    assert!(b.add_fixup(&code, 16, &target, 0, FixupKind::Va64).is_err());
    let (image, layout) = b.build_with_layout().unwrap();
    let offset = layout.sections[0].file_offset.unwrap() as usize;
    assert_eq!(&image.buffer[offset..offset + 4], &3i32.to_le_bytes());
    assert_eq!(
        &image.buffer[offset + 8..offset + 16],
        &(layout.sections[0].virtual_address + 7).to_le_bytes()
    );
    let mut overflow = builder(Target::X86_64);
    let s = overflow.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let code = overflow
        .add_section(&s, SectionSpec::new("__text", vec![0; 4]))
        .unwrap();
    let target = overflow.add_symbol("_x", &code, 0).unwrap();
    overflow
        .add_fixup(&code, 0, &target, i64::MAX, FixupKind::Rel32 { origin: 0 })
        .unwrap();
    assert!(overflow.build().is_err());
}
#[test]
fn arm64_branch_and_page_fixups_preserve_instruction_bits() {
    let mut b = builder(Target::Arm64);
    let s = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let mut spec = SectionSpec::new(
        "__text",
        [0x14000000u32, 0x90000000, 0x91000000, 0xd65f03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    );
    spec.alignment = 2;
    let code = b.add_section(&s, spec).unwrap();
    let target = b.add_symbol("_target", &code, 12).unwrap();
    b.add_fixup(&code, 0, &target, 0, FixupKind::Arm64Branch26)
        .unwrap();
    b.add_fixup(&code, 4, &target, 0, FixupKind::Arm64Page21)
        .unwrap();
    b.add_fixup(&code, 8, &target, 0, FixupKind::Arm64PageOffset12)
        .unwrap();
    let (image, layout) = b.build_with_layout().unwrap();
    let offset = layout.sections[0].file_offset.unwrap() as usize;
    assert_eq!(offset, 304);
    assert_eq!(
        &image.buffer[offset..offset + 12],
        &[0x14000003u32, 0x90000000, 0x9104f000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>()
    );
}
#[test]
fn arm64_rejects_bad_instructions_alignment_range_and_foreign_symbols() {
    for (instruction, addend, kind) in [
        (0u32, 0, FixupKind::Arm64Branch26),
        (0x14000000, 2, FixupKind::Arm64Branch26),
        (0x14000000, 1 << 27, FixupKind::Arm64Branch26),
        (0x90000000, 1i64 << 32, FixupKind::Arm64Page21),
        (0x91400000, 0, FixupKind::Arm64PageOffset12),
    ] {
        let mut b = builder(Target::Arm64);
        let s = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
        let mut spec = SectionSpec::new("__text", instruction.to_le_bytes().to_vec());
        spec.alignment = 2;
        let code = b.add_section(&s, spec).unwrap();
        let target = b.add_symbol("_x", &code, 0).unwrap();
        b.add_fixup(&code, 0, &target, addend, kind).unwrap();
        assert!(b.build().is_err());
    }
    let mut a = builder(Target::X86_64);
    let s = a.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let code = a
        .add_section(&s, SectionSpec::new("__text", vec![0; 8]))
        .unwrap();
    let foreign = a.add_symbol("_x", &code, 0).unwrap();
    let mut b = builder(Target::X86_64);
    let s = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let code = b
        .add_section(&s, SectionSpec::new("__text", vec![0; 8]))
        .unwrap();
    assert!(b.add_fixup(&code, 0, &foreign, 0, FixupKind::Va64).is_err());
}
#[test]
fn structural_dylib_has_install_name_and_rejects_entry() {
    let mut b = MachOBuilder::new_dylib(
        Target::Arm64,
        Version {
            major: 13,
            minor: 0,
            patch: 0,
        },
        "@rpath/libexample.dylib",
    )
    .unwrap();
    let text = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let code = b
        .add_section(
            &text,
            SectionSpec::new("__text", vec![0xc0, 0x03, 0x5f, 0xd6]),
        )
        .unwrap();
    assert!(b.set_entry(&code, 0).is_err());
    let image = b.build().unwrap();
    assert_eq!(&image.buffer[12..16], &6u32.to_le_bytes());
    assert_eq!(&image.buffer[208..212], &13u32.to_le_bytes());
    assert_eq!(&image.buffer[232..256], b"@rpath/libexample.dylib\0");
    assert_eq!(b.build().unwrap().buffer, image.buffer);
}

#[test]
fn arm64_signed_negative_and_lower_bound_encodings() {
    for (kind, instruction, addend, expected) in [
        (
            FixupKind::Arm64Branch26,
            0x14000000u32,
            -4i64,
            0x17ffffffu32,
        ),
        (
            FixupKind::Arm64Branch26,
            0x14000000,
            -(1i64 << 27),
            0x16000000,
        ),
        (FixupKind::Arm64Page21, 0x90000000, -4096, 0xf0ffffe0),
        (
            FixupKind::Arm64Page21,
            0x90000000,
            -(1i64 << 32),
            0x90800000,
        ),
    ] {
        let mut b = builder(Target::Arm64);
        let first = b.add_segment(SegmentSpec::new("__FIRST", 1)).unwrap();
        b.add_section(&first, SectionSpec::new("__data", vec![0]))
            .unwrap();
        let text = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
        let mut spec = SectionSpec::new("__text", instruction.to_le_bytes().to_vec());
        spec.alignment = 2;
        let code = b.add_section(&text, spec).unwrap();
        let target = b.add_symbol("_target", &code, 0).unwrap();
        b.add_fixup(&code, 0, &target, addend, kind).unwrap();
        let (image, layout) = b.build_with_layout().unwrap();
        let offset = layout.sections[1].file_offset.unwrap() as usize;
        assert_eq!(&image.buffer[offset..offset + 4], &expected.to_le_bytes());
    }
    for (kind, instruction, addend) in [
        (FixupKind::Arm64Branch26, 0x14000000u32, -(1i64 << 27) - 4),
        (FixupKind::Arm64Page21, 0x90000000, -(1i64 << 32) - 4096),
    ] {
        let mut b = builder(Target::Arm64);
        let first = b.add_segment(SegmentSpec::new("__FIRST", 1)).unwrap();
        b.add_section(&first, SectionSpec::new("__data", vec![0]))
            .unwrap();
        let text = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
        let mut spec = SectionSpec::new("__text", instruction.to_le_bytes().to_vec());
        spec.alignment = 2;
        let code = b.add_section(&text, spec).unwrap();
        let target = b.add_symbol("_target", &code, 0).unwrap();
        b.add_fixup(&code, 0, &target, addend, kind).unwrap();
        assert!(b.build().is_err());
    }
}

#[test]
fn zero_length_zero_fill_and_foreign_layout() {
    let mut a = builder(Target::X86_64);
    let mut b = builder(Target::X86_64);
    let segment = a.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
    let zero = a
        .add_section(&segment, SectionSpec::zero_fill("__bss", 0))
        .unwrap();
    let symbol = a.add_symbol("_empty", &zero, 0).unwrap();
    let (_, layout) = a.build_with_layout().unwrap();
    assert_eq!(layout.sections[0].size, 0);
    assert_eq!(layout.sections[0].file_offset, None);
    let segment = b.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
    b.add_section(&segment, SectionSpec::zero_fill("__bss", 0))
        .unwrap();
    let (_, foreign) = b.build_with_layout().unwrap();
    assert!(a.symbol_address(&symbol, &foreign).is_err());
}

#[test]
fn absolute_va_rejects_unsigned_conversion_underflow() {
    let mut b = builder(Target::X86_64);
    let segment = b.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
    let section = b
        .add_section(&segment, SectionSpec::new("__data", vec![0; 8]))
        .unwrap();
    let symbol = b.add_symbol("_target", &section, 0).unwrap();
    b.add_fixup(&section, 0, &symbol, i64::MIN, FixupKind::Va64)
        .unwrap();
    assert!(b.build().is_err());
    assert!(b.build().is_err());
}

#[test]
fn absolute_va_rejects_unsigned_conversion_overflow_without_allocating_zero_fill() {
    let mut b = builder(Target::X86_64);
    let data = b.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
    let source = b
        .add_section(&data, SectionSpec::new("__data", vec![0; 8]))
        .unwrap();
    let storage = b.add_segment(SegmentSpec::new("__BSS", 3)).unwrap();
    let size = u64::MAX - 0x1_0000_1000 - 0x1fff;
    let zero = b
        .add_section(&storage, SectionSpec::zero_fill("__bss", size))
        .unwrap();
    let target = b.add_symbol("_high", &zero, size - 1).unwrap();
    b.add_fixup(&source, 0, &target, 16384, FixupKind::Va64)
        .unwrap();
    assert!(b.build().is_err());
}

#[test]
fn generated_linkedit_virtual_range_must_not_wrap() {
    let mut b = builder(Target::X86_64);
    let data = b.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
    b.add_section(&data, SectionSpec::new("__data", vec![0; 8]))
        .unwrap();
    let storage = b.add_segment(SegmentSpec::new("__BSS", 3)).unwrap();
    let zero = b
        .add_section(
            &storage,
            SectionSpec::zero_fill("__bss", u64::MAX - 0x1_0000_1000 - 0xfff),
        )
        .unwrap();
    b.add_symbol("_bss", &zero, 0).unwrap();
    assert!(b.build().is_err());
}

fn linkedit_blob(image: &[u8], command: u32) -> &[u8] {
    let mut pos = 32;
    let count = u32::from_le_bytes(image[16..20].try_into().unwrap());
    for _ in 0..count {
        let cmd = u32::from_le_bytes(image[pos..pos + 4].try_into().unwrap());
        let size = u32::from_le_bytes(image[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if cmd == command {
            let offset = u32::from_le_bytes(image[pos + 8..pos + 12].try_into().unwrap()) as usize;
            let length = u32::from_le_bytes(image[pos + 12..pos + 16].try_into().unwrap()) as usize;
            return &image[offset..offset + length];
        }
        pos += size;
    }
    panic!("command missing")
}
#[test]
fn dyld_chained_import_export_rebase_profiles() {
    for target in [Target::X86_64, Target::Arm64] {
        let mut b = builder(target);
        b.enable_dyld().unwrap();
        let dep = b.add_dependency("/usr/lib/libSystem.B.dylib").unwrap();
        b.add_rpath("@loader_path").unwrap();
        let text = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
        let code = b
            .add_section(&text, SectionSpec::new("__text", vec![0xc3; 8]))
            .unwrap();
        b.set_entry(&code, 0).unwrap();
        let function = b.add_symbol("_answer", &code, 0).unwrap();
        b.add_symbol("_answer_pointer", &code, 4).unwrap();
        let data = b.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
        let mut spec = SectionSpec::new("__data", vec![0; 24]);
        spec.alignment = 3;
        let data = b.add_section(&data, spec).unwrap();
        b.add_import("_getpid", &dep, &data, 0).unwrap();
        b.add_fixup(&data, 8, &function, 0, FixupKind::Va64)
            .unwrap();
        let (image, layout) = b.build_with_layout().unwrap();
        let chains =
            hexspell::macho::dyld::decode_chained_fixups(linkedit_blob(&image.buffer, 0x80000034))
                .unwrap();
        assert_eq!(chains.imports[0].name, "_getpid");
        assert_eq!(chains.imports[0].library_ordinal, 1);
        assert_eq!(chains.segments[0].segment_index, 2);
        let offset = layout.sections[1].file_offset.unwrap() as usize;
        let pointer = u64::from_le_bytes(image.buffer[offset..offset + 8].try_into().unwrap());
        assert_eq!(pointer, (1u64 << 63) | (2u64 << 51));
        let rebased = u64::from_le_bytes(image.buffer[offset + 8..offset + 16].try_into().unwrap());
        assert_eq!(rebased, layout.sections[0].virtual_address - 0x1_0000_0000);
        let exports =
            hexspell::macho::dyld::decode_export_trie(linkedit_blob(&image.buffer, 0x80000033))
                .unwrap();
        assert_eq!(exports[0].name, "_answer");
        assert_eq!(exports[1].name, "_answer_pointer");
        // dyld searches by the first edge byte: every sibling must be distinct.
        fn check_radix(data: &[u8], offset: usize) {
            fn number(data: &[u8], pos: &mut usize) -> usize {
                let mut n = 0;
                let mut shift = 0;
                loop {
                    let byte = data[*pos];
                    *pos += 1;
                    n |= usize::from(byte & 127) << shift;
                    if byte & 128 == 0 {
                        return n;
                    }
                    shift += 7;
                }
            }
            let mut pos = offset;
            let terminal = number(data, &mut pos);
            pos += terminal;
            let count = data[pos];
            pos += 1;
            let mut seen = Vec::new();
            for _ in 0..count {
                let first = data[pos];
                assert!(!seen.contains(&first));
                seen.push(first);
                while data[pos] != 0 {
                    pos += 1;
                }
                pos += 1;
                let child = number(data, &mut pos);
                check_radix(data, child);
            }
        }
        check_radix(linkedit_blob(&image.buffer, 0x80000033), 0);
        assert_eq!(
            exports[0].address,
            Some(layout.sections[0].virtual_address - 0x1_0000_0000)
        );
        assert_eq!(b.build().unwrap().buffer, image.buffer);
        for n in 0..linkedit_blob(&image.buffer, 0x80000034).len() {
            assert!(hexspell::macho::dyld::decode_chained_fixups(
                &linkedit_blob(&image.buffer, 0x80000034)[..n]
            )
            .is_err());
        }
    }
}
#[test]
fn dyld_rejects_overlapping_imports_fixups_and_text_rebases() {
    let mut b = builder(Target::X86_64);
    b.enable_dyld().unwrap();
    let dep = b.add_dependency("/usr/lib/libSystem.B.dylib").unwrap();
    let text = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let code = b
        .add_section(&text, SectionSpec::new("__text", vec![0; 16]))
        .unwrap();
    b.set_entry(&code, 0).unwrap();
    let symbol = b.add_symbol("_main", &code, 0).unwrap();
    assert!(b.add_import("_x", &dep, &code, 0).is_err());
    b.add_fixup(&code, 0, &symbol, 0, FixupKind::Va64).unwrap();
    assert!(b.build().is_err());
}
#[test]
fn runtime_metadata_types_and_foreign_handles() {
    let mut b = builder(Target::Arm64);
    b.enable_dyld().unwrap();
    let dep = b.add_dependency("/usr/lib/libSystem.B.dylib").unwrap();
    let text = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let code = b
        .add_section(&text, SectionSpec::new("__text", vec![0xc0, 3, 0x5f, 0xd6]))
        .unwrap();
    b.set_entry(&code, 0).unwrap();
    let sym = b.add_symbol("_main", &code, 0).unwrap();
    let data = b.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
    b.add_initializers(&data, core::slice::from_ref(&sym))
        .unwrap();
    b.add_terminators(&data, &[sym]).unwrap();
    b.add_thread_local(&data, &dep, 0x11223344u64.to_le_bytes().to_vec(), 3)
        .unwrap();
    assert!(b.add_thread_local(&data, &dep, vec![0; 8], 3).is_err());
    assert!(b.add_unwind(&text, vec![0xff; 4]).is_err());
    let image = b.build().unwrap();
    let flags: Vec<_> = image.sections.iter().map(|s| s.flags() & 255).collect();
    assert_eq!(flags.iter().filter(|f| **f == 9).count(), 2);
    assert!(flags.contains(&17));
    assert!(flags.contains(&19));
}

#[test]
fn dyld_dysymtab_partitions_defined_symbols_without_locals() {
    let mut b = builder(Target::X86_64);
    b.enable_dyld().unwrap();
    let text = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let code = b
        .add_section(&text, SectionSpec::new("__text", vec![0xc3]))
        .unwrap();
    b.set_entry(&code, 0).unwrap();
    b.add_symbol("_main", &code, 0).unwrap();
    assert!(b.add_symbol("_main", &code, 0).is_err());
    let image = b.build().unwrap();
    let mut pos = 32;
    let mut found = false;
    while pos < 32 + u32::from_le_bytes(image.buffer[20..24].try_into().unwrap()) as usize {
        let cmd = u32::from_le_bytes(image.buffer[pos..pos + 4].try_into().unwrap());
        if cmd == 0xb {
            assert_eq!(
                &image.buffer[pos + 8..pos + 32],
                &[0u32, 0, 0, 1, 1, 0]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>()
            );
            found = true;
        }
        pos += u32::from_le_bytes(image.buffer[pos + 4..pos + 8].try_into().unwrap()) as usize;
    }
    assert!(found);
    let mut pos = 32;
    let mut uuid = None;
    while pos < 32 + u32::from_le_bytes(image.buffer[20..24].try_into().unwrap()) as usize {
        let cmd = u32::from_le_bytes(image.buffer[pos..pos + 4].try_into().unwrap());
        if cmd == 0x1b {
            uuid = Some(&image.buffer[pos + 8..pos + 24]);
        }
        pos += u32::from_le_bytes(image.buffer[pos + 4..pos + 8].try_into().unwrap()) as usize;
    }
    let uuid = uuid.unwrap();
    assert!(uuid.iter().any(|b| *b != 0));
    assert_eq!(uuid[6] & 0xf0, 0x40);
    assert_eq!(uuid[8] & 0xc0, 0x80);
}

#[test]
fn modern_terminators_require_libsystem_and_emit_registration_import() {
    for target in [Target::X86_64, Target::Arm64] {
        let mut b = builder(target);
        b.enable_dyld().unwrap();
        let text = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
        let code = b
            .add_section(&text, SectionSpec::new("__text", vec![0xc3; 8]))
            .unwrap();
        b.set_entry(&code, 0).unwrap();
        let function = b.add_symbol("_terminate", &code, 0).unwrap();
        let data = b.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
        let before = b.build().unwrap().buffer;
        assert!(b
            .add_terminators(&data, core::slice::from_ref(&function))
            .is_err());
        assert_eq!(b.build().unwrap().buffer, before);
        b.add_dependency("/usr/lib/libSystem.B.dylib").unwrap();
        b.add_terminators(&data, core::slice::from_ref(&function))
            .unwrap();
        let image = b.build().unwrap();
        let metadata = image.chained_fixups().unwrap().unwrap();
        assert_eq!(metadata.imports[0].name, "___cxa_atexit");
        assert_eq!(
            image
                .sections
                .iter()
                .filter(|s| s.flags() & 255 == 9)
                .count(),
            1
        );
        assert!(!image.sections.iter().any(|s| s.flags() & 255 == 10));
        let registrations = image
            .sections
            .iter()
            .find(|s| s.name() == "__fini_code")
            .unwrap();
        let offset = registrations.offset() as usize;
        match target {
            Target::X86_64 => {
                assert_eq!(&image.buffer[offset..offset + 4], &[0x55, 0x48, 0x89, 0xe5])
            }
            Target::Arm64 => assert_eq!(
                &image.buffer[offset..offset + 4],
                &0xa9bf7bfdu32.to_le_bytes()
            ),
        }
    }
}
