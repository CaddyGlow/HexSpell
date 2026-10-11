#![cfg(all(feature = "macho", feature = "write"))]
use hexspell::macho::{edit::MachOEdit, MachO};
fn put(b: &mut [u8], at: usize, value: u64, width: usize) {
    b[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
fn image(signed: bool) -> MachO {
    let mut b = vec![0; 320];
    b[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    put(&mut b, 4, 0x01000007, 4);
    put(&mut b, 8, 3, 4);
    put(&mut b, 12, 2, 4);
    put(&mut b, 16, if signed { 2 } else { 1 }, 4);
    put(&mut b, 20, if signed { 168 } else { 152 }, 4);
    put(&mut b, 32, 0x19, 4);
    put(&mut b, 36, 152, 4);
    b[40..48].copy_from_slice(b"__CUSTOM");
    put(&mut b, 56, 0x1000, 8);
    put(&mut b, 64, 16, 8);
    put(&mut b, 72, 256, 8);
    put(&mut b, 80, 16, 8);
    put(&mut b, 96, 1, 4);
    b[104..110].copy_from_slice(b"__data");
    b[120..128].copy_from_slice(b"__CUSTOM");
    put(&mut b, 136, 0x1000, 8);
    put(&mut b, 144, 16, 8);
    put(&mut b, 152, 256, 4);
    b[256..272].copy_from_slice(b"original payload");
    if signed {
        put(&mut b, 184, 0x1d, 4);
        put(&mut b, 188, 16, 4);
    }
    MachO::from_buffer(b).unwrap()
}
#[test]
fn custom_payload_commit_preserves_addresses_and_headers() {
    let mut macho = image(false);
    let original = macho.buffer.clone();
    let mut edit = MachOEdit::new(&mut macho).unwrap();
    edit.replace_custom_section(0, b"new").unwrap();
    assert_eq!(edit.commit().unwrap().changed_ranges, vec![256..272]);
    assert_eq!(macho.sections[0].addr(), 0x1000);
    assert_eq!(&macho.buffer[..256], &original[..256]);
    assert_eq!(&macho.buffer[256..272], b"new\0\0\0\0\0\0\0\0\0\0\0\0\0");
}
#[test]
fn signed_images_and_growth_are_rejected_atomically() {
    let mut signed = image(true);
    let original = signed.buffer.clone();
    assert!(MachOEdit::new(&mut signed).is_err());
    assert_eq!(signed.buffer, original);
    let mut macho = image(false);
    let original = macho.buffer.clone();
    let mut edit = MachOEdit::new(&mut macho).unwrap();
    assert!(edit.replace_custom_section(0, &[0; 17]).is_err());
    edit.replace_custom_section(0, b"").unwrap();
    drop(edit);
    assert_eq!(macho.buffer, original);
}
#[test]
fn rejects_header_overlap_and_zero_fill() {
    for (at, value) in [(152, 32), (168, 1)] {
        let mut macho = image(false);
        put(&mut macho.buffer, at, value, 4);
        let original = macho.buffer.clone();
        let mut edit = MachOEdit::new(&mut macho).unwrap();
        assert!(edit.replace_custom_section(0, b"new").is_err());
        drop(edit);
        assert_eq!(macho.buffer, original);
    }
}

#[test]
fn symbol_table_ranges_and_segment_aliases_are_checked() {
    for overlap in [false, true] {
        let mut macho = image(false);
        put(&mut macho.buffer, 16, 2, 4);
        put(&mut macho.buffer, 20, 176, 4);
        put(&mut macho.buffer, 184, 2, 4);
        put(&mut macho.buffer, 188, 24, 4);
        put(&mut macho.buffer, 200, if overlap { 256 } else { 300 }, 4);
        put(&mut macho.buffer, 204, 8, 4);
        let mut edit = MachOEdit::new(&mut macho).unwrap();
        assert_eq!(edit.replace_custom_section(0, b"x").is_err(), overlap);
        if !overlap {
            edit.commit().unwrap();
        }
    }
    let mut macho = image(false);
    put(&mut macho.buffer, 136, 0x1001, 8);
    let mut edit = MachOEdit::new(&mut macho).unwrap();
    assert!(edit.replace_custom_section(0, b"x").is_err());
}

#[test]
fn builder_custom_payload_can_be_edited() {
    use hexspell::macho::build::*;
    for target in [Target::X86_64, Target::Arm64] {
        let mut builder = MachOBuilder::new(
            target,
            Version {
                major: 13,
                minor: 0,
                patch: 0,
            },
        );
        let text = builder.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
        let code = builder
            .add_section(&text, SectionSpec::new("__text", vec![0xc3]))
            .unwrap();
        builder.set_entry(&code, 0).unwrap();
        builder.add_symbol("_main", &code, 0).unwrap();
        let custom = builder
            .add_segment(SegmentSpec::new("__CUSTOM", 1))
            .unwrap();
        builder
            .add_section(&custom, SectionSpec::new("__data", vec![42; 16]))
            .unwrap();
        let mut macho = builder.build().unwrap();
        let code_address = macho.sections[0].addr();
        let custom_offset = macho.sections[1].offset() as usize;
        let mut edit = MachOEdit::new(&mut macho).unwrap();
        edit.replace_custom_section(1, b"edited").unwrap();
        edit.commit().unwrap();
        assert_eq!(macho.sections[0].addr(), code_address);
        assert_eq!(&macho.buffer[custom_offset..custom_offset + 6], b"edited");
    }
}

#[test]
fn dylib_and_rpath_strings_use_only_reserved_capacity() {
    for command in [0xd, 0xc, 0x8000001c] {
        let mut macho = image(false);
        put(&mut macho.buffer, 16, 2, 4);
        put(&mut macho.buffer, 20, 200, 4);
        put(&mut macho.buffer, 184, command, 4);
        put(&mut macho.buffer, 188, 48, 4);
        put(&mut macho.buffer, 192, 24, 4);
        macho.buffer[208..212].copy_from_slice(b"old\0");
        let before = macho.buffer.clone();
        let mut edit = MachOEdit::new(&mut macho).unwrap();
        assert!(edit.replace_command_string(1, &"x".repeat(24)).is_err());
        edit.replace_command_string(1, "new/longer").unwrap();
        edit.commit().unwrap();
        assert_eq!(&macho.buffer[208..219], b"new/longer\0");
        assert_eq!(&macho.buffer[..208], &before[..208]);
        assert_eq!(&macho.buffer[232..], &before[232..]);
    }
}

#[test]
fn fat_edit_preserves_other_slice_and_failed_plan_is_atomic() {
    use hexspell::macho::{
        edit::edit_fat_slice,
        fat::{FatArch, FatHeader},
    };
    let thin = image(false);
    let arch = FatArch {
        cpu_type: 0x01000007,
        cpu_subtype: 3,
        offset: 0,
        size: 0,
        align: 4,
    };
    let mut fat = FatHeader::build(&[(arch.clone(), &thin.buffer), (arch, &thin.buffer)]).unwrap();
    let original = fat.clone();
    assert!(edit_fat_slice(&mut fat, 0, |edit| {
        edit.replace_custom_section(0, b"new")?;
        edit.replace_custom_section(0, b"again")
    })
    .is_err());
    assert_eq!(fat, original);
    edit_fat_slice(&mut fat, 0, |edit| edit.replace_custom_section(0, b"new")).unwrap();
    let header = FatHeader::parse(&fat).unwrap().unwrap();
    let first = header.arches[0].offset as usize;
    assert_eq!(&fat[first + 256..first + 259], b"new");
    assert_eq!(&fat[..first + 256], &original[..first + 256]);
    assert_eq!(&fat[first + 272..], &original[first + 272..]);
}

#[test]
fn custom_growth_preserves_va_and_rejects_virtual_overlap() {
    let mut macho = image(false);
    let original = macho.buffer.clone();
    let mut edit = MachOEdit::new(&mut macho).unwrap();
    edit.grow_custom_section(0, &[0x5a; 8192]).unwrap();
    let report = edit.commit().unwrap();
    assert!(report.virtual_addresses_preserved);
    assert_eq!(macho.sections[0].addr(), 0x1000);
    assert_eq!(macho.sections[0].size(), 8192);
    assert_eq!(macho.sections[0].offset(), 4096);
    assert_eq!(&macho.buffer[256..272], &original[256..272]);
    assert_eq!(&macho.buffer[4096..12288], &[0x5a; 8192]);
}

#[test]
fn append_custom_uses_only_verified_command_slack() {
    let mut macho = image(false);
    macho.buffer[40..48].copy_from_slice(b"__TEXT\0\0");
    macho.buffer[120..128].copy_from_slice(b"__TEXT\0\0");
    // Reserve enough file-backed header slack before the text payload.
    macho.buffer.resize(1024, 0);
    let payload = macho.buffer[256..272].to_vec();
    macho.buffer[256..272].fill(0);
    macho.buffer[512..528].copy_from_slice(&payload);
    put(&mut macho.buffer, 72, 512, 8);
    put(&mut macho.buffer, 152, 512, 4);
    let original = macho.buffer.clone();
    let mut edit = MachOEdit::new(&mut macho).unwrap();
    assert_eq!(edit.add_custom_section("__meta", &[1; 1024]).unwrap(), 1);
    edit.commit().unwrap();
    assert_eq!(macho.sections[0].addr(), 0x1000);
    assert_eq!(macho.sections[1].segment_name(), "__CUSTOM");
    assert_eq!(&macho.buffer[512..528], &original[512..528]);
    let mut no_capacity = image(false);
    no_capacity.buffer[40..48].copy_from_slice(b"__TEXT\0\0");
    no_capacity.buffer[120..128].copy_from_slice(b"__TEXT\0\0");
    let original = no_capacity.buffer.clone();
    let mut edit = MachOEdit::new(&mut no_capacity).unwrap();
    assert!(edit.add_custom_section("__meta", b"x").is_err());
    drop(edit);
    assert_eq!(no_capacity.buffer, original);
}

#[test]
fn explicit_signature_strip_preserves_source_until_commit() {
    use hexspell::macho::edit::SignaturePolicy;
    let mut macho = image(true);
    // Empty signatures still require an explicit policy.
    put(&mut macho.buffer, 192, 320, 4);
    let original = macho.buffer.clone();
    let edit = MachOEdit::with_signature_policy(&mut macho, SignaturePolicy::Strip).unwrap();
    drop(edit);
    assert_eq!(macho.buffer, original);
    let mut edit = MachOEdit::with_signature_policy(&mut macho, SignaturePolicy::Strip).unwrap();
    edit.grow_custom_section(0, &[2; 1024]).unwrap();
    assert!(edit.commit().unwrap().requires_signing);
    assert!(macho.load_commands.iter().all(|c| c.cmd.value != 0x1d));
    assert_eq!(macho.sections[0].addr(), 0x1000);
}

#[test]
fn chained_fixup_payload_alias_is_rejected() {
    let mut macho = image(false);
    put(&mut macho.buffer, 16, 2, 4);
    put(&mut macho.buffer, 20, 168, 4);
    put(&mut macho.buffer, 184, 0x80000034, 4);
    put(&mut macho.buffer, 188, 16, 4);
    put(&mut macho.buffer, 192, 256, 4);
    put(&mut macho.buffer, 196, 16, 4);
    let original = macho.buffer.clone();
    let mut edit = MachOEdit::new(&mut macho).unwrap();
    assert!(edit.grow_custom_section(0, &[0; 32]).is_err());
    drop(edit);
    assert_eq!(macho.buffer, original);
}

#[test]
fn fat_rebuild_grows_one_slice_preserving_other_architecture_bytes() {
    use hexspell::macho::{
        edit::{rebuild_fat_slice, SignaturePolicy},
        fat::{FatArch, FatHeader},
    };
    let first = image(false);
    let mut second = image(false);
    put(&mut second.buffer, 4, 0x100000c, 4);
    let arches = [
        FatArch {
            cpu_type: 0x1000007,
            cpu_subtype: 3,
            offset: 0,
            size: 0,
            align: 12,
        },
        FatArch {
            cpu_type: 0x100000c,
            cpu_subtype: 3,
            offset: 0,
            size: 0,
            align: 14,
        },
    ];
    let mut buffer = FatHeader::build(&[
        (arches[0].clone(), &first.buffer),
        (arches[1].clone(), &second.buffer),
    ])
    .unwrap();
    rebuild_fat_slice(&mut buffer, 0, SignaturePolicy::Reject, |edit| {
        edit.grow_custom_section(0, &[9; 32768])
    })
    .unwrap();
    let fat = FatHeader::parse(&buffer).unwrap().unwrap();
    assert_eq!(fat.arches[0].align, 12);
    assert_eq!(fat.arches[1].align, 14);
    assert_eq!(
        fat.slice_ref(&buffer, &fat.arches[1]).unwrap(),
        second.buffer
    );
    assert!(fat.arches[0].size > first.buffer.len() as u64);
    let changed =
        MachO::from_buffer(fat.slice_ref(&buffer, &fat.arches[0]).unwrap().to_vec()).unwrap();
    assert_eq!(changed.sections[0].addr(), 0x1000);
}

#[test]
fn empty_signature_at_zero_can_be_explicitly_stripped() {
    use hexspell::macho::edit::SignaturePolicy;
    let mut macho = image(true);
    let edit = MachOEdit::with_signature_policy(&mut macho, SignaturePolicy::Strip).unwrap();
    assert!(edit.commit().unwrap().requires_signing);
    assert_eq!(macho.load_commands.len(), 1);
}

#[test]
fn malformed_large_ranges_reject_instead_of_panicking() {
    use hexspell::macho::edit::SignaturePolicy;
    let mut macho = image(true);
    // A malformed segment file range overflows when determining signature ownership.
    put(&mut macho.buffer, 72, u64::MAX, 8);
    put(&mut macho.buffer, 80, 16, 8);
    let original = macho.buffer.clone();
    assert!(MachOEdit::with_signature_policy(&mut macho, SignaturePolicy::Strip).is_err());
    assert_eq!(macho.buffer, original);
}

#[test]
fn growth_within_reserved_segment_keeps_linkedit_last() {
    let mut macho = image(false);
    macho.buffer.resize(512, 0);
    put(&mut macho.buffer, 80, 16, 8);
    put(&mut macho.buffer, 64, 64, 8);
    put(&mut macho.buffer, 16, 2, 4);
    put(&mut macho.buffer, 20, 224, 4);
    put(&mut macho.buffer, 184, 0x19, 4);
    put(&mut macho.buffer, 188, 72, 4);
    macho.buffer[192..202].copy_from_slice(b"__LINKEDIT");
    put(&mut macho.buffer, 208, 0x2000, 8);
    put(&mut macho.buffer, 216, 4096, 8);
    put(&mut macho.buffer, 224, 320, 8);
    put(&mut macho.buffer, 232, 192, 8);
    let mut edit = MachOEdit::new(&mut macho).unwrap();
    assert!(edit.grow_custom_section(0, &[3; 8192]).is_err());
    edit.grow_custom_section(0, &[3; 32]).unwrap();
    edit.commit().unwrap();
    assert_eq!(macho.buffer.len(), 512);
    assert_eq!(macho.sections[0].offset(), 256);
    assert_eq!(macho.sections[0].size(), 32);
    assert_eq!(macho.segments[0].filesize(), 32);
    assert_eq!(macho.segments.last().unwrap().name(), "__LINKEDIT");
    assert_eq!(macho.segments.last().unwrap().fileoff(), 320);
}

#[test]
fn strip_truncates_signature_and_updates_linkedit_extent() {
    use hexspell::macho::edit::SignaturePolicy;
    let mut macho = image(true);
    put(&mut macho.buffer, 16, 3, 4);
    put(&mut macho.buffer, 20, 240, 4);
    // Move the custom section out of the expanded load-command table.
    macho.buffer.resize(8192, 0);
    put(&mut macho.buffer, 72, 4096, 8);
    put(&mut macho.buffer, 152, 4096, 4);
    macho.buffer[200..272].fill(0);
    put(&mut macho.buffer, 200, 0x19, 4);
    put(&mut macho.buffer, 204, 72, 4);
    macho.buffer[208..218].copy_from_slice(b"__LINKEDIT");
    put(&mut macho.buffer, 224, 0x2000, 8);
    put(&mut macho.buffer, 232, 4096, 8);
    put(&mut macho.buffer, 240, 6000, 8);
    put(&mut macho.buffer, 248, 2192, 8);
    put(&mut macho.buffer, 192, 8000, 4);
    put(&mut macho.buffer, 196, 192, 4);
    let edit = MachOEdit::with_signature_policy(&mut macho, SignaturePolicy::Strip).unwrap();
    assert!(edit.commit().unwrap().requires_signing);
    assert_eq!(macho.buffer.len(), 8000);
    assert_eq!(macho.segments[1].filesize(), 2000);
    assert_eq!(macho.segments[1].vmsize(), 4096);
    assert_eq!(macho.sections[0].addr(), 0x1000);
}

fn chained_custom_image(bind: bool, pointer_in_custom: bool) -> MachO {
    use hexspell::macho::build::*;
    let mut builder = MachOBuilder::new_dylib(
        Target::X86_64,
        Version {
            major: 13,
            minor: 0,
            patch: 0,
        },
        "@rpath/probe.dylib",
    )
    .unwrap();
    builder.enable_dyld().unwrap();
    let text = builder.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let code = builder
        .add_section(&text, SectionSpec::new("__text", vec![0xc3]))
        .unwrap();
    let function = builder.add_symbol("_function", &code, 0).unwrap();
    let data = builder.add_segment(SegmentSpec::new("__DATA", 3)).unwrap();
    let mut spec = SectionSpec::new("__pointers", vec![0; 16]);
    spec.alignment = 3;
    let pointers = builder.add_section(&data, spec).unwrap();
    let custom = builder
        .add_segment(SegmentSpec::new("__CUSTOM", 3))
        .unwrap();
    let mut spec = SectionSpec::new("__payload", vec![0; 16]);
    spec.alignment = 3;
    let payload = builder.add_section(&custom, spec).unwrap();
    let slot = if pointer_in_custom {
        &payload
    } else {
        &pointers
    };
    if bind {
        let dep = builder
            .add_dependency("/usr/lib/libSystem.B.dylib")
            .unwrap();
        builder.add_import("_getpid", &dep, slot, 0).unwrap();
    } else {
        builder
            .add_fixup(slot, 0, &function, 0, FixupKind::Va64)
            .unwrap();
    }
    // The second slot ensures traversal checks every node, not just the page start.
    builder
        .add_fixup(slot, 8, &function, 0, FixupKind::Va64)
        .unwrap();
    builder.build().unwrap()
}

#[test]
fn custom_edits_reject_live_chained_bind_and_rebase_slots() {
    for bind in [false, true] {
        let mut image = chained_custom_image(bind, true);
        let original = image.buffer.clone();
        let mut edit = MachOEdit::new(&mut image).unwrap();
        assert!(edit.replace_custom_section(2, &[0; 16]).is_err());
        assert!(edit.grow_custom_section(2, &[0; 32]).is_err());
        edit.commit().unwrap();
        assert_eq!(image.buffer, original);
    }
}

#[test]
fn custom_edit_preserves_unrelated_chained_pointers() {
    let mut image = chained_custom_image(true, false);
    let at = image.sections[1].offset() as usize;
    let original = image.buffer[at..at + 16].to_vec();
    let mut edit = MachOEdit::new(&mut image).unwrap();
    edit.grow_custom_section(2, &[9; 32]).unwrap();
    edit.commit().unwrap();
    assert_eq!(&image.buffer[at..at + 16], original.as_slice());
}

#[test]
fn custom_edit_checks_nodes_after_the_first_chained_pointer() {
    let mut image = chained_custom_image(false, true);
    let header = image.sections[2].record_offset();
    let address = image.sections[2].addr();
    let offset = image.sections[2].offset();
    // The first chain word remains segment data outside this narrowed section.
    put(&mut image.buffer, header + 32, address + 8, 8);
    put(&mut image.buffer, header + 40, 8, 8);
    put(&mut image.buffer, header + 48, u64::from(offset) + 8, 4);
    let original = image.buffer.clone();
    let mut edit = MachOEdit::new(&mut image).unwrap();
    assert!(edit.replace_custom_section(2, &[0; 8]).is_err());
    edit.commit().unwrap();
    assert_eq!(image.buffer, original);
}

#[test]
fn custom_edits_reject_malformed_chained_locations() {
    for corruption in 0..5 {
        let mut image = chained_custom_image(true, false);
        let at = image.sections[1].offset() as usize;
        match corruption {
            0 => put(&mut image.buffer, at, (1u64 << 63) | 99, 8), // absent import
            1 => put(&mut image.buffer, at, 4095u64 << 51, 8),     // next crosses page
            2 => put(&mut image.buffer, at, 1u64 << 51, 8),        // overlapping words
            3 => put(&mut image.buffer, at, 1u64 << 44, 8),        // reserved rebase bit
            _ => {
                let command = image
                    .load_commands
                    .iter()
                    .find(|c| c.cmd.value == 0x80000034)
                    .unwrap();
                let blob = image
                    .byte_order()
                    .read_u32(&image.buffer, command.cmd.offset + 8)
                    .unwrap() as usize;
                let starts = blob
                    + image
                        .byte_order()
                        .read_u32(&image.buffer, blob + 4)
                        .unwrap() as usize;
                // Dylibs have TEXT, DATA, CUSTOM, LINKEDIT segment indices.
                let data_record = starts
                    + image
                        .byte_order()
                        .read_u32(&image.buffer, starts + 8)
                        .unwrap() as usize;
                put(&mut image.buffer, data_record + 8, u64::MAX, 8);
            }
        }
        let original = image.buffer.clone();
        let mut edit = MachOEdit::new(&mut image).unwrap();
        assert!(
            edit.replace_custom_section(2, &[1; 16]).is_err(),
            "corruption {corruption}"
        );
        edit.commit().unwrap();
        assert_eq!(image.buffer, original);
    }
}

#[test]
fn custom_edits_reject_uninventoried_legacy_runtime_writes() {
    for size_at in [12, 20, 28, 36] {
        let mut image = image(false);
        put(&mut image.buffer, 16, 2, 4);
        put(&mut image.buffer, 20, 200, 4);
        put(&mut image.buffer, 184, 0x80000022, 4);
        put(&mut image.buffer, 188, 48, 4);
        put(&mut image.buffer, 184 + size_at - 4, 300, 4);
        put(&mut image.buffer, 184 + size_at, 1, 4);
        let original = image.buffer.clone();
        let mut edit = MachOEdit::new(&mut image).unwrap();
        assert!(edit.replace_custom_section(0, b"new").is_err());
        edit.commit().unwrap();
        assert_eq!(image.buffer, original);
    }
}

#[test]
fn custom_growth_rejects_chained_slots_in_segment_padding() {
    for relocate in [false, true] {
        let mut image = chained_custom_image(false, true);
        let section = image.sections[2].record_offset();
        let payload = image.sections[2].offset() as usize;
        put(&mut image.buffer, section + 40, 8, 8);
        image.buffer[payload..payload + 16].fill(0);
        let command = image
            .load_commands
            .iter()
            .find(|c| c.cmd.value == 0x80000034)
            .unwrap();
        let blob = image
            .byte_order()
            .read_u32(&image.buffer, command.cmd.offset + 8)
            .unwrap() as usize;
        let starts = blob
            + image
                .byte_order()
                .read_u32(&image.buffer, blob + 4)
                .unwrap() as usize;
        let record = starts
            + image
                .byte_order()
                .read_u32(&image.buffer, starts + 12)
                .unwrap() as usize;
        put(&mut image.buffer, record + 22, 8, 2); // A zero-valued rebase in padding.
        if relocate {
            // Structural image with final CUSTOM mapping and unmapped link-edit tables.
            let linkedit = image
                .segments
                .iter()
                .find(|s| s.name() == "__LINKEDIT")
                .unwrap();
            let base = match linkedit {
                hexspell::macho::segment::SegmentEntry::Segment64(s) => s.segname.offset - 8,
                _ => unreachable!(),
            };
            let end = 32 + image.header.sizeofcmds.value as usize;
            image.buffer.copy_within(base + 72..end, base);
            image.buffer[end - 72..end].fill(0);
            put(
                &mut image.buffer,
                16,
                u64::from(image.header.ncmds.value - 1),
                4,
            );
            put(
                &mut image.buffer,
                20,
                u64::from(image.header.sizeofcmds.value - 72),
                4,
            );
        }
        let original = image.buffer.clone();
        let mut edit = MachOEdit::new(&mut image).unwrap();
        assert!(edit
            .grow_custom_section(2, &vec![9; if relocate { 8192 } else { 16 }])
            .is_err());
        edit.commit().unwrap();
        assert_eq!(image.buffer, original);
    }
}

#[test]
fn custom_edits_reject_external_and_local_runtime_relocations() {
    for at in [64, 72] {
        let mut image = image(false);
        image.buffer.resize(400, 0);
        image.buffer[184..264].fill(0);
        put(&mut image.buffer, 16, 2, 4);
        put(&mut image.buffer, 20, 232, 4);
        put(&mut image.buffer, 72, 320, 8);
        put(&mut image.buffer, 152, 320, 4);
        put(&mut image.buffer, 184, 0xb, 4);
        put(&mut image.buffer, 188, 80, 4);
        put(&mut image.buffer, 184 + at, 360, 4);
        put(&mut image.buffer, 184 + at + 4, 1, 4);
        let original = image.buffer.clone();
        let mut edit = MachOEdit::new(&mut image).unwrap();
        assert!(edit.replace_custom_section(0, b"new").is_err());
        edit.commit().unwrap();
        assert_eq!(image.buffer, original);
    }
}
