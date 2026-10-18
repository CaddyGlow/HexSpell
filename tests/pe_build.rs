#![cfg(all(feature = "pe", feature = "write"))]

use hexspell::pe::{build::*, header::ImageBase, PE};
fn builder(target: Target) -> (PeBuilder, SectionId, SymbolId) {
    let mut b = PeBuilder::new(target, ImageKind::Executable);
    let sec = b
        .add_section(SectionSpec::new(".text", vec![0xc3; 64], 0x60000020))
        .unwrap();
    let symbol = b.define_symbol(&sec, 0).unwrap();
    b.set_entry_point(&symbol).unwrap();
    (b, sec, symbol)
}
#[test]
fn headers_layout_determinism_and_virtual_tails() {
    for t in [Target::X86, Target::X64] {
        let (mut b, _, s) = builder(t);
        let mut spec = SectionSpec::new(".bss", vec![], 0xc0000080);
        spec.virtual_size = 8192;
        let sec = b.add_section(spec).unwrap();
        let end = b.define_symbol(&sec, 8192).unwrap();
        let (pe, l) = b.build_with_layout().unwrap();
        assert_eq!(pe.buffer, b.build().unwrap().buffer);
        assert_eq!(pe.sections.len(), 2);
        assert_eq!(pe.sections[1].size_of_raw_data.value, 0);
        assert!(l.symbol(&end).unwrap().file_offset.is_none());
        assert_eq!(l.symbol(&s).unwrap().rva, 0x1000);
        assert_eq!(pe.optional_header.entry_point.size, 4);
        let (other, _, _) = builder(t);
        assert!(other.build_with_layout().unwrap().1.symbol(&s).is_none());
        assert_eq!(PE::from_buffer(pe.buffer).unwrap().sections.len(), 2);
    }
}
#[test]
fn imports_exports_and_rebase() {
    for t in [Target::X86, Target::X64] {
        let (mut b, sec, s) = builder(t);
        let imp = b.add_import("KERNEL32.dll", "ExitProcess").unwrap();
        b.add_import_ordinal("KERNEL32.dll", 12).unwrap();
        b.add_import("USER32.dll", "MessageBoxW").unwrap();
        b.add_import("KERNEL32.dll", "ExitProcess").unwrap();
        b.set_export_base(5).unwrap();
        b.add_export(7, Some("Zed"), &s).unwrap();
        b.add_export(5, Some("Alpha"), &s).unwrap();
        b.add_export(8, None, &s).unwrap();
        let width = if t == Target::X86 { 4 } else { 8 };
        b.add_fixup(Fixup {
            section: sec.clone(),
            offset: 8,
            target: FixupTarget::Symbol(s.clone()),
            kind: if width == 4 {
                FixupKind::Va32
            } else {
                FixupKind::Va64
            },
            addend: 0,
        })
        .unwrap();
        b.add_fixup(Fixup {
            section: sec,
            offset: 24,
            target: FixupTarget::Import(imp.clone()),
            kind: FixupKind::Rva32,
            addend: 0,
        })
        .unwrap();
        let (mut pe, l) = b.build_with_layout().unwrap();
        assert_eq!(pe.imports().unwrap().dlls.len(), 2);
        let ex = pe.exports().unwrap().unwrap();
        assert_eq!(ex.directory.base.value, 5);
        assert_eq!(ex.functions.len(), 4);
        assert_eq!(
            ex.named.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            ["Alpha", "Zed"]
        );
        assert_eq!(pe.imports_iter().unwrap().count(), 2);
        assert_eq!(l.import(&imp).unwrap().file_offset.unwrap() % width, 0);
        let at = l.symbol(&s).unwrap().file_offset.unwrap() + 8;
        let before = pe.buffer[at..at + width].to_vec();
        let newbase = b.image_base + 0x10000;
        pe.apply_image_base(if width == 4 {
            ImageBase::Base32(newbase as u32)
        } else {
            ImageBase::Base64(newbase)
        })
        .unwrap();
        assert_ne!(&pe.buffer[at..at + width], before);
    }
}
#[test]
fn invalid_handles_entries_and_overlapping_fixups() {
    let (mut a, sec, s) = builder(Target::X86);
    let (_, foreign, _) = builder(Target::X86);
    assert!(a.define_symbol(&foreign, 0).is_err());
    let end = a.define_symbol(&sec, 64).unwrap();
    assert!(a.set_entry_point(&end).is_err());
    for offset in [4, 6] {
        a.add_fixup(Fixup {
            section: sec.clone(),
            offset,
            target: FixupTarget::Symbol(s.clone()),
            kind: FixupKind::Va32,
            addend: 0,
        })
        .unwrap();
    }
    assert!(a.build().is_err());
    assert!(a.build().is_err());
}
#[test]
fn tls_and_runtime_directories() {
    for t in [Target::X86, Target::X64] {
        let (mut b, _, callback) = builder(t);
        let data = b
            .add_section(SectionSpec::new(".data", vec![0; 16], 0xc0000040))
            .unwrap();
        let template = b
            .add_section(SectionSpec::new(".tls", vec![1; 16], 0xc0000040))
            .unwrap();
        let start = b.define_symbol(&template, 0).unwrap();
        let end = b.define_symbol(&template, 16).unwrap();
        let index = b.define_symbol(&data, 0).unwrap();
        b.set_tls(TlsSpec {
            start,
            end,
            index,
            callbacks: vec![callback.clone(), callback.clone()],
            zero_fill: 8,
            alignment: 16,
        })
        .unwrap();
        if t == Target::X64 {
            let unwind = b
                .add_section(SectionSpec::new(".xdata", vec![1, 0, 0, 0], 0x40000040))
                .unwrap();
            let u = b.define_symbol(&unwind, 0).unwrap();
            let code = b
                .add_section(SectionSpec::new(".more", vec![0xc3; 4], 0x60000020))
                .unwrap();
            let a = b.define_symbol(&code, 0).unwrap();
            let z = b.define_symbol(&code, 4).unwrap();
            b.add_runtime_function(&a, &z, &u).unwrap();
        }
        let pe = b.build().unwrap();
        let tls = pe.tls().unwrap().unwrap();
        assert_eq!(tls.size_of_zero_fill.value, 8);
        assert_eq!(
            tls.start_address_of_raw_data.size,
            if t == Target::X86 { 4 } else { 8 }
        );
        assert!(!pe.base_relocations().unwrap().is_empty());
        if t == Target::X64 {
            assert_eq!(pe.exceptions().unwrap().unwrap().entries.len(), 1);
        }
    }
}

#[test]
fn checked_relative_boundaries_target_width_and_nondefault_options() {
    for t in [Target::X86, Target::X64] {
        for (delta, accepted) in [
            (i32::MIN as i64, true),
            (i32::MAX as i64, true),
            (i32::MAX as i64 + 1, false),
            (i32::MIN as i64 - 1, false),
        ] {
            let (mut b, section, symbol) = builder(t);
            b.file_alignment = 1024;
            b.section_alignment = 8192;
            b.image_base = 0x10000000;
            b.add_fixup(Fixup {
                section,
                offset: 4,
                target: FixupTarget::Symbol(symbol),
                kind: FixupKind::Rel32 { origin: 0 },
                addend: delta,
            })
            .unwrap();
            assert_eq!(b.build().is_ok(), accepted);
        }
        let (mut b, section, symbol) = builder(t);
        b.add_fixup(Fixup {
            section,
            offset: 60,
            target: FixupTarget::Symbol(symbol),
            kind: FixupKind::Va64,
            addend: 0,
        })
        .unwrap();
        assert!(b.build().is_err());
        let (mut b, _, _) = builder(t);
        b.file_alignment = 3;
        assert!(b.build().is_err());
        b.file_alignment = 512;
        b.image_base = if t == Target::X86 {
            0xffff0000
        } else {
            !65535u64
        };
        let mut section = SectionSpec::new(".bss", vec![], 0xc0000080);
        section.virtual_size = 0x10000;
        b.add_section(section).unwrap();
        assert!(b.build().is_err());
    }
}

#[test]
fn relocations_change_absolute_sites_only_in_both_directions() {
    for target in [Target::X86, Target::X64] {
        let (mut b, section, symbol) = builder(target);
        let width = if target == Target::X86 { 4 } else { 8 };
        for (offset, kind) in [
            (
                0,
                if width == 4 {
                    FixupKind::Va32
                } else {
                    FixupKind::Va64
                },
            ),
            (16, FixupKind::Rva32),
            (24, FixupKind::Rel32 { origin: 28 }),
        ] {
            b.add_fixup(Fixup {
                section: section.clone(),
                offset,
                target: FixupTarget::Symbol(symbol.clone()),
                kind,
                addend: 0,
            })
            .unwrap();
        }
        let (original, layout) = b.build_with_layout().unwrap();
        let at = layout.symbol(&symbol).unwrap().file_offset.unwrap();
        for delta in [-65536i64, 65536] {
            let mut image = PE::from_buffer(original.buffer.clone()).unwrap();
            let base = (b.image_base as i64 + delta) as u64;
            image
                .apply_image_base(if width == 4 {
                    ImageBase::Base32(base as u32)
                } else {
                    ImageBase::Base64(base)
                })
                .unwrap();
            assert_eq!(
                &image.buffer[at + 16..at + 28],
                &original.buffer[at + 16..at + 28]
            );
            let mut bytes = [0; 8];
            bytes[..width].copy_from_slice(&image.buffer[at..at + width]);
            assert_eq!(u64::from_le_bytes(bytes), base + 0x1000);
        }
    }
}

#[test]
fn import_lookup_tables_are_aligned_and_slots_encode_names_ordinals() {
    for target in [Target::X86, Target::X64] {
        let (mut b, _, _) = builder(target);
        let named = b.add_import("a.dll", "AB").unwrap();
        let ordinal = b.add_import_ordinal("b.dll", 23).unwrap();
        let (pe, layout) = b.build_with_layout().unwrap();
        let width = if target == Target::X86 { 4 } else { 8 };
        let read = |at: usize| {
            let mut bytes = [0; 8];
            bytes[..width].copy_from_slice(&pe.buffer[at..at + width]);
            u64::from_le_bytes(bytes)
        };
        for dll in pe.imports().unwrap().dlls {
            assert_eq!(
                dll.descriptor.original_first_thunk.value as usize % width,
                0
            );
            assert_eq!(dll.descriptor.first_thunk.value as usize % width, 0);
        }
        let at = layout.import(&named).unwrap().file_offset.unwrap();
        assert!(read(at) > 0 && read(at) < (1u64 << (width * 8 - 1)));
        assert_eq!(read(at + width), 0);
        let at = layout.import(&ordinal).unwrap().file_offset.unwrap();
        assert_eq!(read(at), (1u64 << (width * 8 - 1)) | 23);
        assert_eq!(read(at + width), 0);
    }
}

#[test]
fn tls_relocation_sites_are_exact_and_null_terminators_survive_rebase() {
    for target in [Target::X86, Target::X64] {
        for count in 0..=2 {
            let (mut b, _, callback) = builder(target);
            let data = b
                .add_section(SectionSpec::new(".data", vec![0; 8], 0xc0000040))
                .unwrap();
            let template = b
                .add_section(SectionSpec::new(".tls", vec![1; 8], 0xc0000040))
                .unwrap();
            let start = b.define_symbol(&template, 0).unwrap();
            let end = b.define_symbol(&template, 8).unwrap();
            let index = b.define_symbol(&data, 0).unwrap();
            b.set_tls(TlsSpec {
                start,
                end,
                index,
                callbacks: vec![callback; count],
                zero_fill: 0,
                alignment: 8,
            })
            .unwrap();
            let mut pe = b.build().unwrap();
            let width = if target == Target::X86 { 4 } else { 8 };
            let dir = &pe.optional_header.data_directories[9];
            let base = dir.virtual_address.value;
            let size = if width == 4 { 24 } else { 40 };
            let expected: Vec<_> = (0..4)
                .map(|n| base + n * width as u32)
                .chain((0..count).map(|n| base + size + n as u32 * width as u32))
                .collect();
            let sites: Vec<_> = pe
                .base_relocations()
                .unwrap()
                .iter()
                .flat_map(|block| {
                    block
                        .entries
                        .iter()
                        .filter(|entry| entry.relocation_type() != 0)
                        .map(|entry| entry.rva(block.page_rva.value))
                })
                .collect();
            assert_eq!(sites, expected);
            let section = pe
                .sections
                .iter()
                .find(|s| s.virtual_address.value == base)
                .unwrap();
            let at = section.pointer_to_raw_data.value as usize;
            let before = pe.buffer[at..at + size as usize + (count + 1) * width].to_vec();
            let new_base = b.image_base + 65536;
            pe.apply_image_base(if width == 4 {
                ImageBase::Base32(new_base as u32)
            } else {
                ImageBase::Base64(new_base)
            })
            .unwrap();
            for n in 0..4 {
                assert_ne!(
                    &pe.buffer[at + n * width..at + (n + 1) * width],
                    &before[n * width..(n + 1) * width]
                );
            }
            let null = at + size as usize + count * width;
            assert_eq!(&pe.buffer[null..null + width], vec![0; width]);
        }
    }
}

#[test]
fn header_summaries_count_only_declared_content_flags() {
    let (mut b, _, _) = builder(Target::X86);
    let ignored = b
        .add_section(SectionSpec::new(".ignored", vec![0; 10], 0x40000000))
        .unwrap();
    let initialized = b
        .add_section(SectionSpec::new(".data", vec![0; 10], 0x40000040))
        .unwrap();
    let mut uninitialized = SectionSpec::new(".bss", vec![], 0xc0000080);
    uninitialized.virtual_size = 700;
    b.add_section(uninitialized).unwrap();
    let (pe, layout) = b.build_with_layout().unwrap();
    assert_eq!(layout.section(&ignored).unwrap().raw_size, 512);
    assert_eq!(pe.optional_header.size_of_code.value, 512);
    assert_eq!(
        pe.optional_header.size_of_initialized_data.value,
        layout.section(&initialized).unwrap().raw_size
    );
    assert_eq!(pe.optional_header.size_of_uninitialized_data.value, 700);
}

#[test]
fn overflow_without_symbols_and_executable_without_entry_are_rejected() {
    let mut b = PeBuilder::new(Target::X64, ImageKind::Dll);
    b.image_base = !65535u64;
    let mut section = SectionSpec::new(".bss", vec![], 0xc0000080);
    section.virtual_size = 0x10000;
    b.add_section(section).unwrap();
    b.add_import("a.dll", "function").unwrap();
    assert!(b.build().is_err());
    let mut b = PeBuilder::new(Target::X64, ImageKind::Executable);
    b.add_section(SectionSpec::new(".text", vec![0xc3], 0x60000020))
        .unwrap();
    assert!(b.build().is_err());
    let mut b = PeBuilder::new(Target::X64, ImageKind::Dll);
    b.add_section(SectionSpec::new(".text", vec![0xc3], 0x60000020))
        .unwrap();
    assert!(b.build().is_ok());
}

#[test]
fn generated_fields_remain_patchable_and_independent_builders_are_deterministic() {
    for target in [Target::X86, Target::X64] {
        let (a, _, _) = builder(target);
        let (b, _, _) = builder(target);
        let mut pe = a.build().unwrap();
        assert_eq!(pe.buffer, b.build().unwrap().buffer);
        let offset = pe.optional_header.subsystem.offset;
        pe.optional_header
            .subsystem
            .update(&mut pe.buffer, 2)
            .unwrap();
        let parsed = PE::from_buffer(pe.buffer).unwrap();
        assert_eq!(parsed.optional_header.subsystem.value, 2);
        assert_eq!(parsed.optional_header.subsystem.offset, offset);
        assert_eq!(parsed.optional_header.subsystem.size, 2);
    }
}

#[test]
fn virtual_only_symbols_resolve_but_cannot_receive_writes_or_be_entries() {
    let (mut b, _, code) = builder(Target::X86);
    let mut data = SectionSpec::new(".tail", vec![0; 4], 0xe0000040);
    data.virtual_size = 100;
    let section = b.add_section(data).unwrap();
    let tail = b.define_symbol(&section, 8).unwrap();
    assert!(b.set_entry_point(&tail).is_err());
    assert!(b
        .build_with_layout()
        .unwrap()
        .1
        .symbol(&tail)
        .unwrap()
        .file_offset
        .is_none());
    b.add_fixup(Fixup {
        section,
        offset: 8,
        target: FixupTarget::Symbol(code),
        kind: FixupKind::Rva32,
        addend: 0,
    })
    .unwrap();
    assert!(b.build().is_err());
}

#[test]
fn x86_named_imports_reject_rvas_that_alias_the_ordinal_flag() {
    for named in [true, false] {
        let mut builder = PeBuilder::new(Target::X86, ImageKind::Dll);
        let mut section = SectionSpec::new(".bss", vec![], 0xc0000080);
        section.virtual_size = 0x8000_0000;
        builder.add_section(section).unwrap();
        if named {
            builder.add_import("a.dll", "Named").unwrap();
            assert!(builder.build().is_err());
        } else {
            builder.add_import_ordinal("a.dll", 23).unwrap();
            let pe = builder.build().unwrap();
            let imports = pe.imports().unwrap();
            assert!(matches!(
                imports.dlls[0].entries[0],
                hexspell::pe::import::ImportEntry::Ordinal { ordinal: 23, .. }
            ));
        }
    }
}
