#![cfg(all(feature = "elf", feature = "write"))]
use hexspell::elf::{
    edit::{BuildIdPolicy, ElfEdit},
    ELF,
};

fn put(bytes: &mut [u8], at: usize, value: u64, width: usize) {
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
fn image(notes: bool) -> ELF {
    let mut b = vec![0; 432];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put(&mut b, 16, 2, 2);
    put(&mut b, 18, 62, 2);
    put(&mut b, 20, 1, 4);
    put(&mut b, 40, 128, 8);
    put(&mut b, 52, 64, 2);
    put(&mut b, 58, 64, 2);
    put(&mut b, 60, 3, 2);
    put(&mut b, 62, 2, 2);
    b[64..80].copy_from_slice(b"original payload");
    b[80..89].copy_from_slice(b"\0.custom\0");
    put(&mut b, 192, 1, 4);
    put(&mut b, 196, 1, 4);
    put(&mut b, 216, 64, 8);
    put(&mut b, 224, 16, 8);
    put(&mut b, 260, 3, 4);
    put(&mut b, 280, 80, 8);
    put(&mut b, 288, 9, 8);
    if notes {
        put(&mut b, 32, 320, 8);
        put(&mut b, 54, 56, 2);
        put(&mut b, 56, 1, 2);
        put(&mut b, 320, 4, 4);
        put(&mut b, 328, 400, 8);
        put(&mut b, 352, 16, 8);
        put(&mut b, 360, 16, 8);
    }
    ELF::from_buffer(b).unwrap()
}
#[test]
fn custom_payload_and_name_commit_preserves_layout() {
    let mut elf = image(false);
    let original = elf.buffer.clone();
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
    edit.replace_custom_section(1, b"new").unwrap();
    edit.rename_custom_section(1, ".new").unwrap();
    let report = edit.commit().unwrap();
    assert_eq!(report.changed_ranges, vec![64..80, 81..89]);
    assert!(!report.build_id_may_be_stale);
    assert_eq!(elf.section_name(1).unwrap(), ".new");
    assert_eq!(&elf.buffer[64..80], b"new\0\0\0\0\0\0\0\0\0\0\0\0\0");
    assert_eq!(elf.buffer[128..], original[128..]);
}
#[test]
fn failed_commit_and_dropped_session_preserve_source() {
    let mut elf = image(true);
    let original = elf.buffer.clone();
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
    edit.replace_custom_section(1, b"new").unwrap();
    assert!(edit.commit().is_err());
    assert_eq!(elf.buffer, original);
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::PreserveStale).unwrap();
    assert!(edit.replace_custom_section(1, &[1; 17]).is_err());
    drop(edit);
    assert_eq!(elf.buffer, original);
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::PreserveStale).unwrap();
    edit.replace_custom_section(1, b"").unwrap();
    assert!(edit.commit().unwrap().build_id_may_be_stale);
    assert_eq!(&elf.buffer[400..416], &original[400..416]);
}
#[test]
fn rejects_allocated_data_header_overlap_and_name_aliases() {
    for (offset, value, width) in [(200, 2, 8), (216, 0, 8), (256, 4, 4)] {
        let mut elf = image(false);
        put(&mut elf.buffer, offset, value, width);
        let original = elf.buffer.clone();
        let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
        let result = if offset == 256 {
            edit.rename_custom_section(1, ".new")
        } else {
            edit.replace_custom_section(1, b"x")
        };
        assert!(result.is_err());
        drop(edit);
        assert_eq!(elf.buffer, original);
    }
}

#[test]
fn builder_custom_metadata_can_be_edited_without_changing_code() {
    use hexspell::elf::build::*;
    let mut builder = ElfBuilder::new(Target::LinuxX86_64);
    let rx = builder.add_segment(SegmentSpec::RX).unwrap();
    let code = builder
        .add_section(Some(&rx), SectionSpec::new(".text", vec![0xc3]))
        .unwrap();
    let entry = builder
        .define_symbol("_start", &code, 0, 1, Binding::Global)
        .unwrap();
    builder.set_entry(&entry).unwrap();
    builder
        .add_section(None, SectionSpec::new(".custom", vec![42; 16]))
        .unwrap();
    let mut elf = builder.build().unwrap();
    let entry = elf.header.entry.value;
    let code_bytes = elf.section_data_by_name(".text").unwrap().unwrap().to_vec();
    let index = elf.section_index_by_name(".custom").unwrap();
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
    edit.replace_custom_section(index, b"edited").unwrap();
    edit.rename_custom_section(index, ".meta").unwrap();
    edit.commit().unwrap();
    assert_eq!(elf.header.entry.value, entry);
    assert_eq!(
        elf.section_data_by_name(".text").unwrap().unwrap(),
        code_bytes
    );
    assert_eq!(
        &elf.section_data_by_name(".meta").unwrap().unwrap()[..6],
        b"edited"
    );
}

#[test]
fn appended_growth_and_addition_preserve_original_file_and_indices() {
    let mut elf = image(false);
    let original = elf.buffer.clone();
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
    edit.grow_custom_section(1, &[0x5a; 1024]).unwrap();
    let index = edit.add_custom_section(".new", b"new payload").unwrap();
    assert_eq!(index, 3);
    let report = edit.commit().unwrap();
    assert_eq!(elf.section_headers[1].sh_addr(), 0);
    assert_eq!(elf.section_headers[1].sh_size(), 1024);
    assert_eq!(elf.section_name(3).unwrap(), ".new");
    assert_eq!(
        elf.section_data_by_name(".new").unwrap().unwrap(),
        b"new payload"
    );
    assert_eq!(&elf.buffer[64..89], &original[64..89]);
    assert_eq!(report.moved_ranges.len(), 2);
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
    edit.remove_custom_section(1).unwrap();
    edit.commit().unwrap();
    assert_eq!(elf.section_headers.len(), 4);
    assert_eq!(elf.section_headers[1].sh_type(), 0);
    assert_eq!(elf.section_name(3).unwrap(), ".new");
}

#[test]
fn removal_rejects_section_references_and_unknown_tables() {
    for kind in [4, 0x70000001] {
        let mut elf = image(false);
        put(&mut elf.buffer, 260, kind, 4);
        put(&mut elf.buffer, 300, 1, 4); // relocation sh_info
        let original = elf.buffer.clone();
        let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
        assert!(edit.remove_custom_section(1).is_err());
        drop(edit);
        assert_eq!(elf.buffer, original);
    }
}

#[test]
fn owned_note_add_replace_and_build_id_removal() {
    let mut elf = image(false);
    let mut note = vec![0; 20];
    put(&mut note, 0, 4, 4);
    put(&mut note, 4, 4, 4);
    put(&mut note, 8, 3, 4);
    note[12..16].copy_from_slice(b"GNU\0");
    note[16..20].copy_from_slice(b"hash");
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Remove).unwrap();
    let index = edit.add_note_section(".note.id", &note).unwrap();
    let report = edit.commit().unwrap();
    assert!(report.build_id_removed);
    assert!(!report.build_id_may_be_stale);
    let data = elf.section_data_by_name(".note.id").unwrap().unwrap();
    assert_eq!(&data[12..16], b"HXS\0");
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::PreserveStale).unwrap();
    assert!(edit.replace_note_section(index, &note[..16]).is_err());
    edit.replace_note_section(index, &note).unwrap();
    assert!(edit.commit().unwrap().build_id_may_be_stale);
}

#[test]
fn malformed_owned_notes_reject_before_source_change() {
    let mut elf = image(false);
    let original = elf.buffer.clone();
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Remove).unwrap();
    assert!(edit.add_note_section(".note.bad", &[0xff; 16]).is_err());
    drop(edit);
    assert_eq!(elf.buffer, original);
}

#[test]
fn interpreter_edit_is_bounded_and_transactional() {
    let mut elf = image(true);
    put(&mut elf.buffer, 320, 3, 4);
    elf.buffer[400..416].copy_from_slice(b"/lib/ld-test.so\0");
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
    assert!(edit
        .replace_interpreter("/a/very/long/interpreter/path")
        .is_err());
    edit.replace_interpreter("/ld.so").unwrap();
    edit.commit().unwrap();
    assert_eq!(&elf.buffer[400..407], b"/ld.so\0");
}

#[test]
fn appending_elf32_big_endian_retains_disk_field_widths() {
    let mut bytes = vec![0; 256];
    bytes[..7].copy_from_slice(b"\x7fELF\x01\x02\x01");
    for (at, value, width) in [
        (16, 2u64, 2),
        (18, 3, 2),
        (20, 1, 4),
        (32, 128, 4),
        (40, 52, 2),
        (46, 40, 2),
        (48, 3, 2),
        (50, 2, 2),
        (168, 1, 4),
        (172, 1, 4),
        (184, 64, 4),
        (188, 8, 4),
        (212, 3, 4),
        (224, 72, 4),
        (228, 9, 4),
    ] {
        bytes[at..at + width].copy_from_slice(&value.to_be_bytes()[8 - width..]);
    }
    bytes[64..72].copy_from_slice(b"original");
    bytes[72..81].copy_from_slice(b"\0.custom\0");
    let mut elf = ELF::from_buffer(bytes).unwrap();
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
    edit.grow_custom_section(1, &[7; 256]).unwrap();
    edit.add_custom_section(".extra", b"big endian").unwrap();
    edit.commit().unwrap();
    assert_eq!(elf.header.sh_off.size, 4);
    assert_eq!(elf.section_name(3).unwrap(), ".extra");
    assert_eq!(elf.section_headers[1].sh_size(), 256);
    assert_eq!(
        elf.section_data_by_name(".extra").unwrap().unwrap(),
        b"big endian"
    );
}

#[test]
fn interpreter_cannot_alias_header_or_unrelated_section() {
    let mut elf = image(true);
    put(&mut elf.buffer, 320, 3, 4);
    put(&mut elf.buffer, 328, 16, 8);
    let original = elf.buffer.clone();
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
    assert!(edit.replace_interpreter("x").is_err());
    drop(edit);
    assert_eq!(elf.buffer, original);
}

#[test]
fn bounded_dynamic_strings_reject_capacity_and_shared_aliases() {
    use hexspell::elf::build::*;
    let mut builder = ElfBuilder::new(Target::LinuxX86_64);
    builder.set_image_kind(ImageKind::SharedObject);
    builder.set_soname("liboriginal.so").unwrap();
    builder.add_import_slot("libc.so.6", "getpid").unwrap();
    let mut elf = builder.build().unwrap();
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
    assert!(edit
        .replace_dynamic_string(14, 0, "lib-too-long-for-capacity.so")
        .is_err());
    edit.replace_dynamic_string(14, 0, "libnew.so").unwrap();
    edit.replace_dynamic_string(1, 0, "libc.so.6").unwrap();
    edit.commit().unwrap();
    let table = elf.dynamic().unwrap().unwrap();
    let soname = table.find(14).unwrap().value() as usize;
    let strings = elf
        .section_headers
        .iter()
        .find(|s| s.sh_type() == 6)
        .unwrap()
        .sh_link() as usize;
    let start = elf.section_headers[strings].sh_offset() as usize;
    assert_eq!(
        &elf.buffer[start + soname..start + soname + 11],
        b"libnew.so\0\0"
    );
    // Point a second string consumer at a suffix of the owned name.
    let mut needed = table.find(1).unwrap().d_val.clone();
    let order = elf.byte_order().unwrap();
    needed
        .update_with(&mut elf.buffer, (soname + 3) as u64, order)
        .unwrap();
    let original = elf.buffer.clone();
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
    assert!(edit.replace_dynamic_string(14, 0, "libx.so").is_err());
    drop(edit);
    assert_eq!(elf.buffer, original);
}

#[test]
fn unbounded_custom_alignment_rejects_before_allocation() {
    let mut elf = image(false);
    put(&mut elf.buffer, 240, 1u64 << 63, 8);
    let original = elf.buffer.clone();
    let mut edit = ElfEdit::new(&mut elf, BuildIdPolicy::Reject).unwrap();
    assert!(edit.grow_custom_section(1, b"new").is_err());
    drop(edit);
    assert_eq!(elf.buffer, original);
}
