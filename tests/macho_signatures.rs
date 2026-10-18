#![cfg(all(feature = "macho", feature = "write"))]
use hexspell::macho::{build::*, load_command::LC_CODE_SIGNATURE, segment::SegmentEntry, MachO};
fn image(target: Target) -> MachO {
    let mut b = MachOBuilder::new(
        target,
        Version {
            major: 13,
            minor: 0,
            patch: 0,
        },
    );
    b.enable_dyld().unwrap();
    let text = b.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let code = b
        .add_section(&text, SectionSpec::new("__text", vec![0xc3; 4]))
        .unwrap();
    b.set_entry(&code, 0).unwrap();
    b.add_symbol("_main", &code, 0).unwrap();
    b.build().unwrap()
}
#[test]
fn reservation_then_write_preserves_every_hashed_byte_and_mapped_address() {
    for target in [Target::X86_64, Target::Arm64] {
        let mut macho = image(target);
        let addresses: Vec<_> = macho
            .sections
            .iter()
            .map(|s| (s.addr(), s.offset()))
            .collect();
        let commands = macho.header.ncmds.value;
        assert!(macho.code_signature_data().unwrap().is_none());
        let layout = macho.reserve_code_signature(5001).unwrap();
        assert!(layout.signature_range.start.is_multiple_of(16));
        assert_eq!(layout.signature_range.len(), 5001);
        assert_eq!(macho.header.ncmds.value, commands + 1);
        let prefix = macho.buffer[layout.signing_range.clone()].to_vec();
        let blob = vec![0x5a; 5001];
        macho.write_code_signature(&blob).unwrap();
        assert_eq!(macho.code_signature_data().unwrap().unwrap(), blob);
        assert_eq!(&macho.buffer[layout.signing_range.clone()], prefix);
        assert_eq!(
            macho
                .sections
                .iter()
                .map(|s| (s.addr(), s.offset()))
                .collect::<Vec<_>>(),
            addresses
        );
        let linkedit = macho
            .segments
            .iter()
            .find(|s| s.name() == "__LINKEDIT")
            .unwrap();
        assert_eq!(
            linkedit.fileoff() + linkedit.filesize(),
            macho.buffer.len() as u64
        );
        assert!(linkedit.vmsize() >= linkedit.filesize());
        let before = macho.buffer.clone();
        assert_eq!(macho.reserve_code_signature(5001).unwrap(), layout);
        assert_eq!(macho.buffer, before);
        assert!(macho.write_code_signature(&blob[..5000]).is_err());
        assert_eq!(macho.buffer, before);
        let new_layout = macho.reserve_code_signature(17).unwrap();
        assert_eq!(macho.header.ncmds.value, commands + 1);
        assert_eq!(
            new_layout.signature_range.start,
            layout.signature_range.start
        );
        macho.write_code_signature(&[3; 17]).unwrap();
        macho.remove_code_signature().unwrap();
        assert_eq!(macho.header.ncmds.value, commands);
        assert!(macho.code_signature().unwrap().is_none());
        assert_eq!(macho.buffer.len(), layout.signature_range.start);
        let before = macho.buffer.clone();
        macho.remove_code_signature().unwrap();
        assert_eq!(macho.buffer, before);
    }
}
#[test]
fn reservations_reject_occupied_padding_unknown_commands_and_invalid_layouts() {
    for kind in 0..5 {
        let mut macho = image(Target::X86_64);
        let command_end = 32 + macho.header.sizeofcmds.value as usize;
        match kind {
            0 => macho.buffer[command_end] = 1,
            1 => {
                let at = macho.load_commands.last().unwrap().cmd.offset;
                macho.buffer[at..at + 4].copy_from_slice(&0x7777u32.to_le_bytes());
            }
            2 => {
                let at = match macho.segments.last().unwrap() {
                    SegmentEntry::Segment64(s) => s.filesize.offset,
                    _ => unreachable!(),
                };
                macho.buffer[at..at + 8].copy_from_slice(&1u64.to_le_bytes());
            }
            3 => {
                let at = match &macho.sections[0] {
                    hexspell::macho::section::SectionEntry::Section64(s) => s.offset.offset,
                    _ => unreachable!(),
                };
                macho.buffer[at..at + 4].copy_from_slice(&(command_end as u32).to_le_bytes());
            }
            _ => {}
        }
        let before = macho.buffer.clone();
        assert!(
            macho
                .reserve_code_signature(if kind == 4 { 0 } else { 32 })
                .is_err(),
            "kind {kind}"
        );
        assert_eq!(macho.buffer, before);
    }
}
#[test]
fn malformed_aliases_and_duplicate_signature_commands_are_rejected() {
    for kind in 0..5 {
        let mut macho = image(Target::Arm64);
        let layout = macho.reserve_code_signature(32).unwrap();
        let command = macho
            .load_commands
            .iter()
            .find(|c| c.cmd.value == LC_CODE_SIGNATURE)
            .unwrap()
            .cmd
            .offset;
        match kind {
            0 => macho.buffer[command + 12..command + 16].copy_from_slice(&u32::MAX.to_le_bytes()),
            1 => macho.buffer[command + 8..command + 12].copy_from_slice(&32u32.to_le_bytes()),
            2 => {
                let next = command + 16;
                let original = macho.buffer[command..next].to_vec();
                macho.buffer[next..next + 16].copy_from_slice(&original);
                let order = macho.byte_order();
                order.write_u32(&mut macho.buffer, 16, macho.header.ncmds.value + 1);
                order.write_u32(&mut macho.buffer, 20, macho.header.sizeofcmds.value + 16);
            }
            4 => {
                let target_end = layout.signature_range.end as u64;
                let order = macho.byte_order();
                macho.segments[1]
                    .filesize_mut()
                    .update_with(&mut macho.buffer, target_end, order)
                    .unwrap();
                macho.segments[1]
                    .vmsize_mut()
                    .update_with(&mut macho.buffer, target_end, order)
                    .unwrap();
            }
            _ => {
                let at = match &macho.sections[0] {
                    hexspell::macho::section::SectionEntry::Section64(s) => s.offset.offset,
                    _ => unreachable!(),
                };
                macho.buffer[at..at + 4]
                    .copy_from_slice(&(layout.signature_range.start as u32).to_le_bytes());
            }
        }
        let before = macho.buffer.clone();
        assert!(macho.write_code_signature(&[0; 32]).is_err(), "kind {kind}");
        assert!(macho.remove_code_signature().is_err(), "kind {kind}");
        assert_eq!(macho.buffer, before);
    }
}

#[test]
fn reservation_rejects_entry_points_in_command_padding() {
    for target in [Target::X86_64, Target::Arm64] {
        for delta in [0, 8, 12, 15, 16] {
            let mut macho = image(target);
            let padding = 32 + macho.header.sizeofcmds.value as usize;
            let command = macho
                .load_commands
                .iter()
                .find(|c| c.cmd.value == hexspell::macho::load_command::LC_MAIN)
                .unwrap();
            let at = command.cmd.offset + 8;
            macho.buffer[at..at + 8].copy_from_slice(&((padding + delta) as u64).to_le_bytes());
            let before = macho.buffer.clone();

            let result = macho.reserve_code_signature(32);

            if delta < 16 {
                assert!(result.is_err(), "entry point at padding + {delta}");
                assert_eq!(macho.buffer, before);
            } else {
                assert!(result.is_ok());
            }
        }
    }
}

#[test]
fn equal_size_reservation_preserves_external_segment_rounding() {
    let mut macho = image(Target::X86_64);
    let layout = macho.reserve_code_signature(5001).unwrap();
    let index = macho
        .segments
        .iter()
        .position(|s| s.name() == "__LINKEDIT")
        .unwrap();
    let order = macho.byte_order();
    macho.segments[index]
        .vmsize_mut()
        .update_with(&mut macho.buffer, 32768, order)
        .unwrap();
    let original = macho.buffer.clone();
    assert_eq!(macho.reserve_code_signature(5001).unwrap(), layout);
    assert_eq!(macho.buffer, original);
    macho.write_code_signature(&vec![1; 5001]).unwrap();
    assert_eq!(
        &macho.buffer[layout.signing_range.clone()],
        &original[layout.signing_range]
    );
}

#[test]
fn oversized_reservation_fails_before_allocating_or_mutating() {
    let mut macho = image(Target::Arm64);
    let original = macho.buffer.clone();
    assert!(macho.reserve_code_signature(u32::MAX).is_err());
    assert_eq!(macho.buffer, original);
}
