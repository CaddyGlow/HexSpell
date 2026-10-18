#![cfg(all(feature = "elf", feature = "write"))]
use hexspell::elf::build::*;
fn executable() -> (ElfBuilder, SectionId, SymbolId) {
    let mut b = ElfBuilder::new(Target::LinuxX86_64);
    let segment = b.add_segment(SegmentSpec::RX).unwrap();
    let section = b
        .add_section(
            Some(&segment),
            SectionSpec::new(
                ".text",
                vec![
                    0xb8, 60, 0, 0, 0, 0xbf, 42, 0, 0, 0, 0x0f, 0x05, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )
        .unwrap();
    let symbol = b
        .define_symbol("_start", &section, 0, 12, Binding::Global)
        .unwrap();
    b.set_entry(&symbol).unwrap();
    (b, section, symbol)
}
#[test]
fn static_layout_and_symbols_are_deterministic() {
    let (b, _, _) = executable();
    let (image, layout) = b.build_with_layout().unwrap();
    assert_eq!(image.buffer, b.build().unwrap().buffer);
    assert_eq!(&image.buffer[..7], b"\x7fELF\x02\x01\x01");
    assert_eq!(layout.entry, 0x401000);
    assert_eq!(layout.sections[0].file_offset, Some(4096));
    assert_eq!(image.header.entry.value, 0x401000);
    assert_eq!(image.section_name(1).unwrap(), ".text");
    assert!(image.symbols().unwrap().is_some());
    assert_eq!(
        u64::from_le_bytes(
            image.buffer[64 + 112 + 16..64 + 112 + 24]
                .try_into()
                .unwrap()
        ),
        0x401000
    );
}
#[test]
fn zero_fill_does_not_expand_file_and_stripped_images_parse() {
    let (mut b, _, _) = executable();
    let rw = b.add_segment(SegmentSpec::RW).unwrap();
    b.add_section(Some(&rw), SectionSpec::zero_fill(".bss", 1 << 30, 16))
        .unwrap();
    let (image, layout) = b.build_with_layout().unwrap();
    assert_eq!(layout.sections[1].file_offset, None);
    assert!(image.buffer.len() < 16384);
    b.emit_section_table(false);
    let image = b.build().unwrap();
    assert_eq!(image.header.sh_num.value, 0);
    assert!(image.section_headers.is_empty());
}
#[test]
fn fixups_are_checked_and_foreign_handles_rejected() {
    let (mut b, section, symbol) = executable();
    b.add_fixup(&section, 12, &symbol, FixupKind::Absolute64, 0)
        .unwrap();
    assert!(b
        .add_fixup(&section, 13, &symbol, FixupKind::Absolute32, 0)
        .is_err());
    let image = b.build().unwrap();
    assert_eq!(
        u64::from_le_bytes(image.buffer[4108..4116].try_into().unwrap()),
        0x401000
    );
    let (_, foreign, foreign_symbol) = executable();
    assert!(b.set_entry(&foreign_symbol).is_err());
    assert!(b
        .define_symbol("bad", &foreign, 0, 0, Binding::Local)
        .is_err());
}
#[test]
fn failed_build_leaves_specification_reusable() {
    let (mut b, section, symbol) = executable();
    b.add_fixup(&section, 12, &symbol, FixupKind::Absolute32, i64::MAX)
        .unwrap();
    assert!(b.build().is_err());
    assert!(b.build().is_err());
}
#[test]
fn rejects_entry_in_zero_fill_and_initialized_data_after_zero_fill() {
    let (mut b, _, _) = executable();
    let rx = b.add_segment(SegmentSpec::RX).unwrap();
    let zero = b
        .add_section(Some(&rx), SectionSpec::zero_fill(".bss", 4096, 1))
        .unwrap();
    let symbol = b
        .define_symbol("invalid_entry", &zero, 0, 1, Binding::Local)
        .unwrap();
    b.set_entry(&symbol).unwrap();
    assert!(b.build().is_err());
}
#[test]
fn shared_object_has_dynamic_symbols_and_relative_relocations() {
    let (mut b, code, _) = executable();
    b.set_image_kind(ImageKind::SharedObject);
    b.set_soname("libtest.so").unwrap();
    let data_segment = b.add_segment(SegmentSpec::RW).unwrap();
    let data = b
        .add_section(Some(&data_segment), SectionSpec::new(".data", vec![0; 8]))
        .unwrap();
    let function = b
        .define_symbol("answer", &code, 0, 12, Binding::Global)
        .unwrap();
    b.add_fixup(&data, 0, &function, FixupKind::Absolute64, 0)
        .unwrap();
    let image = b.build().unwrap();
    assert_eq!(&image.buffer[16..18], &3u16.to_le_bytes());
    assert!(image.dynamic().unwrap().is_some());
    assert!(image.dynamic_symbols().unwrap().is_some());
    assert_eq!(image.buffer, b.build().unwrap().buffer);
}
#[test]
fn pie_requires_explicit_interpreter_and_supports_stripped_dynamic_metadata() {
    let (mut b, _, _) = executable();
    b.set_image_kind(ImageKind::Pie);
    assert!(b.build().is_err());
    b.set_interpreter("/lib64/ld-linux-x86-64.so.2").unwrap();
    b.emit_section_table(false);
    let image = b.build().unwrap();
    assert!(image.program_headers.iter().any(|p| p.p_type() == 2));
    assert!(image.program_headers.iter().any(|p| p.p_type() == 3));
}
#[test]
fn eager_import_slots_are_writable_and_encoded_as_glob_dat() {
    let (mut b, code, _) = executable();
    b.set_image_kind(ImageKind::Pie);
    b.set_interpreter("/lib64/ld-linux-x86-64.so.2").unwrap();
    let slot = b.add_import_slot("libc.so.6", "getpid").unwrap();
    b.add_fixup(&code, 12, &slot, FixupKind::PcRelative32, 0)
        .unwrap();
    let image = b.build().unwrap();
    assert!(image.dynamic_symbols().unwrap().is_some());
    assert!(image.section_headers.iter().any(|s| s.sh_type() == 4));
}
#[test]
fn rejects_inconsistent_zero_fill_and_writable_code() {
    let mut builder = ElfBuilder::new(Target::LinuxX86_64);
    assert!(builder
        .add_segment(SegmentSpec {
            read: true,
            write: true,
            execute: true
        })
        .is_err());
    let rx = builder.add_segment(SegmentSpec::RX).unwrap();
    let mut invalid = SectionSpec::new(".invalid", vec![]);
    invalid.zero_fill = 12;
    assert!(builder.add_section(Some(&rx), invalid).is_err());
    let foreign = ElfBuilder::new(Target::LinuxX86_64)
        .add_segment(SegmentSpec::R)
        .unwrap();
    assert!(builder
        .add_section(Some(&foreign), SectionSpec::new(".bad", vec![1]))
        .is_err());
}
#[test]
fn zero_length_nobits_is_preserved_without_file_storage() {
    let (mut builder, _, _) = executable();
    let segment = builder.add_segment(SegmentSpec::RW).unwrap();
    builder
        .add_section(Some(&segment), SectionSpec::new(".data", vec![1]))
        .unwrap();
    builder
        .add_section(Some(&segment), SectionSpec::zero_fill(".bss", 0, 8))
        .unwrap();
    let (image, layout) = builder.build_with_layout().unwrap();
    let index = image.section_index_by_name(".bss").unwrap();
    assert_eq!(image.section_headers[index].sh_type(), 8);
    assert_eq!(layout.sections[2].file_offset, None);
    assert_eq!(layout.sections[2].size, 0);
}
#[test]
fn relative_fixups_encode_end_of_field_origin_and_check_overflow() {
    let (mut builder, section, symbol) = executable();
    builder
        .add_fixup(&section, 12, &symbol, FixupKind::PcRelative32, 0)
        .unwrap();
    let image = builder.build().unwrap();
    assert_eq!(&image.buffer[4108..4112], &(-16i32).to_le_bytes());
    let (mut builder, section, symbol) = executable();
    builder
        .add_fixup(&section, 12, &symbol, FixupKind::PcRelative32, i64::MAX)
        .unwrap();
    assert!(builder.build().is_err());
}
#[test]
fn initialized_section_after_nobits_is_rejected() {
    let (mut builder, _, _) = executable();
    let rw = builder.add_segment(SegmentSpec::RW).unwrap();
    builder
        .add_section(Some(&rw), SectionSpec::zero_fill(".bss", 4096, 8))
        .unwrap();
    builder
        .add_section(Some(&rw), SectionSpec::new(".data", vec![1]))
        .unwrap();
    assert!(builder.build().is_err());
}
#[test]
fn program_header_and_interpreter_precede_load_segments_for_loader_bias() {
    let (mut builder, _, _) = executable();
    builder.set_image_kind(ImageKind::Pie);
    builder
        .set_interpreter("/lib64/ld-linux-x86-64.so.2")
        .unwrap();
    let image = builder.build().unwrap();
    assert_eq!(image.program_headers[0].p_type(), 6);
    assert_eq!(image.program_headers[0].p_vaddr(), 64);
    assert_eq!(
        image.program_headers[0].p_filesz(),
        image.program_headers.len() as u64 * 56
    );
    assert_eq!(image.program_headers[1].p_type(), 3);
    assert_eq!(image.program_headers[2].p_type(), 1);
    assert!(image.program_headers[2].p_filesz() >= 64 + image.program_headers.len() as u64 * 56);
}
#[test]
fn rejected_import_does_not_add_an_orphan_mapping() {
    let (mut builder, section, _) = executable();
    builder
        .define_symbol("__hexspell_import_0", &section, 0, 0, Binding::Local)
        .unwrap();
    let before = builder.build().unwrap().buffer;
    assert!(builder.add_import_slot("libc.so.6", "write").is_err());
    assert_eq!(builder.build().unwrap().buffer, before);
}

#[test]
fn runtime_arrays_tls_and_unwind_have_loader_metadata() {
    let (mut builder, _, function) = executable();
    builder.set_image_kind(ImageKind::SharedObject);
    builder.add_initializer(&function).unwrap();
    builder.add_finalizer(&function).unwrap();
    let tls = builder
        .add_tls_template(vec![1, 2, 3, 4, 0, 0, 0, 0], 8)
        .unwrap();
    builder.add_tls_address_slot(&tls, 4).unwrap();
    let image = builder.build().unwrap();
    assert_eq!(image.buffer, builder.build().unwrap().buffer);
    let tls_header = image
        .program_headers
        .iter()
        .find(|p| p.p_type() == 7)
        .unwrap();
    assert_eq!(tls_header.p_align(), 8);
    assert_eq!(tls_header.p_filesz(), 8);
    let tls_section = image.section_index_by_name(".tdata").unwrap();
    assert_eq!(image.section_headers[tls_section].sh_flags() & 0x400, 0x400);
    let init = image.section_index_by_name(".init_array").unwrap();
    let fini = image.section_index_by_name(".fini_array").unwrap();
    assert_eq!(image.section_headers[init].sh_type(), 14);
    assert_eq!(image.section_headers[fini].sh_type(), 15);
    let relocations = image
        .section_data(image.section_index_by_name(".rela.dyn").unwrap())
        .unwrap();
    assert_eq!(relocations.len(), 72); // two relative array pointers + module ID.
    assert_eq!(
        u64::from_le_bytes(relocations[56..64].try_into().unwrap()),
        16
    );
}
fn unwind_bytes() -> Vec<u8> {
    let mut bytes = vec![
        20, 0, 0, 0, 0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b, 0x0c, 7, 8, 0x90, 1, 0, 0,
    ];
    bytes.extend_from_slice(&[
        16, 0, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0,
    ]);
    bytes.extend_from_slice(&[0; 4]);
    bytes
}
#[test]
fn unwind_pointer_encodings_and_record_inventory_are_checked() {
    let (mut builder, _, function) = executable();
    builder.set_image_kind(ImageKind::SharedObject);
    let mut bad = unwind_bytes();
    bad[16] = 0; // absolute pointer encoding is outside the supported profile.
    let before = builder.build().unwrap().buffer;
    assert!(builder
        .add_eh_frame(bad, &[(24, function.clone())])
        .is_err());
    assert_eq!(builder.build().unwrap().buffer, before);
    assert!(builder
        .add_eh_frame(
            unwind_bytes(),
            &[(24, function.clone()), (24, function.clone())]
        )
        .is_err());
    builder
        .add_eh_frame(unwind_bytes(), &[(24, function)])
        .unwrap();
    let image = builder.build().unwrap();
    assert!(image
        .program_headers
        .iter()
        .any(|p| p.p_type() == 0x6474e550));
    let hdr = image
        .section_data(image.section_index_by_name(".eh_frame_hdr").unwrap())
        .unwrap();
    assert_eq!(&hdr[..4], &[1, 0x1b, 3, 0x3b]);
    assert_eq!(&hdr[8..12], &1u32.to_le_bytes());
    let frame = image
        .section_data(image.section_index_by_name(".eh_frame").unwrap())
        .unwrap();
    assert!(i32::from_le_bytes(frame[32..36].try_into().unwrap()) < 0);
}
#[test]
fn runtime_handles_and_tls_extent_are_validated_atomically() {
    let (mut builder, code, function) = executable();
    let (_, _, foreign) = executable();
    assert!(builder.add_initializer(&foreign).is_err());
    assert!(builder.add_finalizer(&foreign).is_err());
    let data = builder
        .add_section(None, SectionSpec::new(".data", vec![0]))
        .unwrap();
    let data = builder
        .define_symbol("data", &data, 0, 1, Binding::Local)
        .unwrap();
    assert!(builder.add_initializer(&data).is_err());
    assert!(builder.add_tls_address_slot(&code, 0).is_err());
    assert!(builder.add_tls_template(vec![1], 3).is_err());
    let tls = builder.add_tls_template(vec![0; 8], 8).unwrap();
    assert!(builder.add_tls_template(vec![0; 8], 8).is_err());
    assert!(builder.add_tls_address_slot(&tls, 8).is_err());
    builder.add_initializer(&function).unwrap();
    assert!(builder.build().is_err()); // static executable loader never runs arrays.
}
#[test]
fn weak_visibility_and_symbol_version_tables_are_coherent() {
    let (mut builder, code, _) = executable();
    builder.set_image_kind(ImageKind::SharedObject);
    let weak = builder
        .define_symbol("weak", &code, 0, 12, Binding::Weak)
        .unwrap();
    builder
        .set_symbol_visibility(&weak, Visibility::Protected)
        .unwrap();
    builder.set_symbol_version(&weak, "HEXSPELL_1.0").unwrap();
    builder
        .add_versioned_import_slot("libc.so.6", "getpid", "GLIBC_2.2.5")
        .unwrap();
    let image = builder.build().unwrap();
    let symbols = image
        .section_data(image.section_index_by_name(".dynsym").unwrap())
        .unwrap();
    assert_eq!(symbols[48 + 4], 0x20);
    assert_eq!(symbols[48 + 5], 3);
    let versions = image
        .section_data(image.section_index_by_name(".gnu.version").unwrap())
        .unwrap();
    assert_eq!(versions, &[0, 0, 1, 0, 2, 0, 3, 0]);
    assert_eq!(
        image.section_headers[image.section_index_by_name(".gnu.version_d").unwrap()].sh_type(),
        0x6ffffffd
    );
    assert_eq!(
        image.section_headers[image.section_index_by_name(".gnu.version_r").unwrap()].sh_type(),
        0x6ffffffe
    );
    assert_eq!(image.buffer, builder.build().unwrap().buffer);
}
#[test]
fn structural_serialization_checks_class_and_endian_independently() {
    use hexspell::{elf::header::ElfClass, field::ByteOrder};
    use layout::*;
    for class in [ElfClass::Elf32, ElfClass::Elf64] {
        for byte_order in [ByteOrder::Little, ByteOrder::Big] {
            let mut payload = vec![0u8; 80];
            payload[64..70].copy_from_slice(b"\0data\0");
            let header = HeaderSpec {
                class,
                byte_order,
                os_abi: 0,
                image_type: 2,
                machine: 3,
                entry: 0x1234,
                flags: 0,
                section_names: 1,
            };
            let programs = [ProgramSpec {
                kind: 1,
                flags: 4,
                offset: 0,
                virtual_address: 0x1000,
                file_size: 80,
                memory_size: 4096,
                alignment: 4096,
                ..ProgramSpec::default()
            }];
            let sections = [SectionHeaderSpec {
                name: 1,
                kind: 3,
                offset: 64,
                size: 6,
                alignment: 1,
                ..SectionHeaderSpec::default()
            }];
            let image = serialize_layout(header, &payload, &programs, &sections).unwrap();
            assert_eq!(image.section_name(1).unwrap(), "data");
            assert_eq!(image.program_headers[0].p_vaddr(), 0x1000);
            assert_eq!(image.header.entry.value, 0x1234);
            assert_eq!(
                &image.buffer[16..18],
                if byte_order == ByteOrder::Little {
                    &[2, 0]
                } else {
                    &[0, 2]
                }
            );
            assert_eq!(
                image.buffer,
                serialize_layout(header, &payload, &programs, &sections)
                    .unwrap()
                    .buffer
            );
            if class == ElfClass::Elf32 {
                let mut overflow = header;
                overflow.entry = 1u64 << 32;
                assert!(serialize_layout(overflow, &payload, &programs, &sections).is_err());
            }
            assert_eq!(payload[16], 0); // immutable caller layout on success/failure.
        }
    }
}
#[test]
fn structural_extended_section_count_and_string_index_are_encoded_in_section_zero() {
    use hexspell::{elf::header::ElfClass, field::ByteOrder};
    use layout::*;
    let mut payload = vec![0; 80];
    payload[64..71].copy_from_slice(b"\0names\0");
    let mut sections = vec![SectionHeaderSpec::default(); 0xff00];
    sections[0].name = 1;
    sections[0xfeff] = SectionHeaderSpec {
        kind: 3,
        offset: 64,
        size: 7,
        alignment: 1,
        ..SectionHeaderSpec::default()
    };
    let header = HeaderSpec {
        class: ElfClass::Elf32,
        byte_order: ByteOrder::Big,
        os_abi: 0,
        image_type: 2,
        machine: 3,
        entry: 0,
        flags: 0,
        section_names: 0xff00,
    };
    let image = serialize_layout(header, &payload, &[], &sections).unwrap();
    assert_eq!(image.header.sh_num.value, 0);
    assert_eq!(image.header.sh_strndx.value, 0xffff);
    assert_eq!(image.section_headers.len(), 0xff01);
    assert_eq!(image.section_headers[0].sh_size(), 0xff01);
    assert_eq!(image.section_headers[0].sh_link(), 0xff00);
    assert_eq!(image.section_name(1).unwrap(), "names");
}

#[test]
fn structural_extended_program_count_and_virtual_only_storage_are_checked() {
    use hexspell::{elf::header::ElfClass, field::ByteOrder};
    use layout::*;
    let header = HeaderSpec {
        class: ElfClass::Elf64,
        byte_order: ByteOrder::Little,
        os_abi: 0,
        image_type: 2,
        machine: 62,
        entry: 0,
        flags: 0,
        section_names: 0,
    };
    let programs = vec![ProgramSpec::default(); 0xffff];
    let image = serialize_layout(header, &[0; 64], &programs, &[]).unwrap();
    assert_eq!(image.header.ph_num.value, 0xffff);
    assert_eq!(image.program_headers.len(), 0xffff);
    assert_eq!(image.section_headers[0].sh_info(), 0xffff);
    let sections = [SectionHeaderSpec {
        kind: 8,
        size: 1 << 30,
        alignment: 16,
        ..SectionHeaderSpec::default()
    }];
    let image = serialize_layout(header, &[0; 64], &[], &sections).unwrap();
    assert!(image.buffer.len() < 256);
    assert!(image.section_data(1).unwrap().is_empty());
    let overflow = ProgramSpec {
        kind: 1,
        offset: u64::MAX,
        file_size: 1,
        memory_size: 1,
        ..ProgramSpec::default()
    };
    assert!(serialize_layout(header, &[0; 64], &[overflow], &[]).is_err());
    let incongruent = ProgramSpec {
        kind: 1,
        virtual_address: 1,
        alignment: 4096,
        ..ProgramSpec::default()
    };
    assert!(serialize_layout(header, &[0; 64], &[incongruent], &[]).is_err());
}
#[test]
fn version_metadata_rejects_invalid_strings_foreign_handles_and_static_lifecycle() {
    let (mut builder, _, symbol) = executable();
    let (_, _, foreign) = executable();
    let before = builder.build().unwrap().buffer;
    assert!(builder
        .set_symbol_visibility(&foreign, Visibility::Hidden)
        .is_err());
    assert!(builder.set_symbol_version(&foreign, "V1").is_err());
    assert!(builder.set_symbol_version(&symbol, "").is_err());
    assert!(builder
        .add_versioned_import_slot("libc.so.6", "getpid", "bad\0version")
        .is_err());
    assert_eq!(builder.build().unwrap().buffer, before);
    builder.set_symbol_version(&symbol, "V1").unwrap();
    assert!(builder.build().is_err());
    builder.set_image_kind(ImageKind::Pie);
    builder
        .set_interpreter("/lib64/ld-linux-x86-64.so.2")
        .unwrap();
    builder.add_initializer(&symbol).unwrap();
    assert!(builder.build().is_err()); // main-image initialization needs a CRT.
}

#[test]
fn default_visibility_global_pointers_use_preemptible_symbol_relocations() {
    for visibility in [
        Visibility::Default,
        Visibility::Hidden,
        Visibility::Protected,
    ] {
        let (mut builder, _, function) = executable();
        builder.set_image_kind(ImageKind::SharedObject);
        builder
            .set_symbol_visibility(&function, visibility)
            .unwrap();
        let rw = builder.add_segment(SegmentSpec::RW).unwrap();
        let section = builder
            .add_section(Some(&rw), SectionSpec::new(".pointer", vec![0; 8]))
            .unwrap();
        builder
            .add_fixup(&section, 0, &function, FixupKind::Absolute64, 3)
            .unwrap();
        let image = builder.build().unwrap();
        let rela = image
            .section_data(image.section_index_by_name(".rela.dyn").unwrap())
            .unwrap();
        let info = u64::from_le_bytes(rela[8..16].try_into().unwrap());
        let addend = i64::from_le_bytes(rela[16..24].try_into().unwrap());
        if visibility == Visibility::Default {
            assert_eq!(info, (1u64 << 32) | 1); // R_X86_64_64, dynsym[1].
            assert_eq!(addend, 3);
        } else {
            assert_eq!(info, 8); // R_X86_64_RELATIVE: nonpreemptible definition.
            assert_eq!(addend, 4099);
        }
    }
}

#[test]
fn lifecycle_pointers_preserve_binding_and_visibility() {
    for binding in [Binding::Local, Binding::Global, Binding::Weak] {
        for visibility in [
            Visibility::Default,
            Visibility::Hidden,
            Visibility::Protected,
        ] {
            let mut builder = ElfBuilder::new(Target::LinuxX86_64);
            builder.set_image_kind(ImageKind::SharedObject);
            let text = builder.add_segment(SegmentSpec::RX).unwrap();
            let code = builder
                .add_section(Some(&text), SectionSpec::new(".text", vec![0xc3]))
                .unwrap();
            // A preceding global definition tests the actual dynsym index, not a constant 1.
            builder
                .define_symbol("other", &code, 0, 1, Binding::Global)
                .unwrap();
            let function = builder
                .define_symbol("callback", &code, 0, 1, binding)
                .unwrap();
            builder
                .set_symbol_visibility(&function, visibility)
                .unwrap();
            builder.add_initializer(&function).unwrap();
            builder.add_finalizer(&function).unwrap();
            let image = builder.build().unwrap();
            let rela = image
                .section_data(image.section_index_by_name(".rela.dyn").unwrap())
                .unwrap();
            assert_eq!(rela.len(), 48);
            for entry in rela.as_chunks::<24>().0 {
                let info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
                let addend = i64::from_le_bytes(entry[16..24].try_into().unwrap());
                if binding != Binding::Local && visibility == Visibility::Default {
                    assert_eq!(info, (2u64 << 32) | 1); // R_X86_64_64, dynsym[2].
                    assert_eq!(addend, 0);
                } else {
                    assert_eq!(info, 8); // R_X86_64_RELATIVE.
                    assert_eq!(addend, 4096);
                }
            }
        }
    }
}
