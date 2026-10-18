//! Signature containers: bounded payloads, transactional rejection and exact preservation.
use hexspell::{
    elf::{self, signature::AppendedSignature, ELF},
    field::ByteOrder,
    macho::{self, load_command::LC_CODE_SIGNATURE, MachO},
    pe::{self, certificate::CertificateOwned, PE},
};

/// Exercise signature readers and editors on ordinary executable bytes.
/// Errors must leave buffers unchanged; successful edits must preserve payloads
/// and signed prefixes. Payloads are at most 256 bytes; resize probes reserve at most 257.
pub fn signatures(data: &[u8]) {
    if data.len() > crate::INPUT_LIMIT {
        return;
    }
    let payload = if data.is_empty() {
        &[0][..]
    } else {
        &data[..data.len().min(256)]
    };
    if let Ok(Some(signature)) = AppendedSignature::parse(data) {
        assert_eq!(
            signature.signed_data(data).unwrap(),
            &data[signature.signed_range.clone()]
        );
        assert_eq!(
            signature.data(data).unwrap(),
            &data[signature.signature_range.clone()]
        );
    }
    if let Ok(mut image) = PE::from_buffer(data.to_vec()) {
        pe_edits(&mut image, payload);
    }
    if let Ok(mut image) = ELF::from_buffer(data.to_vec()) {
        elf_edits(&mut image, payload);
    }
    if let Ok(mut image) = MachO::from_buffer(data.to_vec()) {
        macho_edits(&mut image, payload);
    }
}

fn pe_edits(image: &mut PE, payload: &[u8]) {
    let original = image.buffer.clone();
    let records = image.owned_certificates();
    if let Ok(table) = &records {
        let serialized = table.serialize().unwrap();
        if let Some(parsed) = image.certificates().unwrap() {
            assert_eq!(
                serialized,
                image.buffer[parsed.offset..parsed.offset + parsed.size]
            );
        } else {
            assert!(serialized.is_empty());
        }
    }
    let added = CertificateOwned::pkcs_signed_data(payload.to_vec());
    match image.append_certificate(&added) {
        Ok(report) => {
            let range = report.range.unwrap();
            assert!(range.start.is_multiple_of(8));
            let current = image.owned_certificates().unwrap();
            let mut expected = records.unwrap();
            expected.certificates.push(added);
            assert_eq!(current.serialize().unwrap(), expected.serialize().unwrap());
            assert_eq!(image.optional_header.checksum.value, image.calc_checksum());
            image.replace_certificates(&current).unwrap();

            // Simulate a buffer-only edit while retaining the original cached headers.
            let mut stale = PE::from_buffer(original.clone()).unwrap();
            stale.buffer = image.buffer.clone();
            let second = CertificateOwned::pkcs_signed_data(vec![0x7a]);
            stale.append_certificate(&second).unwrap();
            expected.certificates.push(second);
            assert_eq!(
                stale.owned_certificates().unwrap().serialize().unwrap(),
                expected.serialize().unwrap()
            );
        }
        Err(_) => assert_eq!(image.buffer, original),
    }
    *image = PE::from_buffer(original.clone()).unwrap();
    if let Ok(table) = records_from_buffer(&original) {
        if image.replace_certificates(&table).is_err() {
            assert_eq!(image.buffer, original);
        } else {
            assert_eq!(
                image.owned_certificates().unwrap().serialize().unwrap(),
                table.serialize().unwrap()
            );
        }
    }
    *image = PE::from_buffer(original.clone()).unwrap();
    match image.remove_certificates() {
        Ok(report) => {
            assert!(image.certificates().unwrap().is_none());
            let end = report.previous_range.map_or(original.len(), |r| r.start);
            assert_eq!(image.buffer.len(), end);
            // Only the directory slot and checksum may change in the retained prefix.
            let directory = &image.optional_header.data_directories[pe::header::SECURITY];
            let mut restored = image.buffer.clone();
            for range in [
                directory.virtual_address.offset..directory.size.offset + 4,
                image.optional_header.checksum.offset..image.optional_header.checksum.offset + 4,
            ] {
                restored[range.clone()].copy_from_slice(&original[range]);
            }
            assert_eq!(restored, original[..end]);
        }
        Err(_) => assert_eq!(image.buffer, original),
    }
}

fn records_from_buffer(
    buffer: &[u8],
) -> hexspell::errors::Result<pe::certificate::CertificateTableOwned> {
    PE::from_buffer(buffer.to_vec())?.owned_certificates()
}

fn elf_edits(image: &mut ELF, payload: &[u8]) {
    let original = image.buffer.clone();
    let previous = AppendedSignature::parse(&original);
    let prefix = previous
        .as_ref()
        .ok()
        .and_then(|s| s.as_ref())
        .map_or(original.len(), |s| s.signed_range.end);
    match image.set_appended_signature(payload) {
        Ok(report) => {
            assert_eq!(report.signed_range, 0..prefix);
            assert_eq!(&image.buffer[..prefix], &original[..prefix]);
            let signature = image.appended_signature().unwrap().unwrap();
            assert_eq!(signature.data(&image.buffer).unwrap(), payload);
            let signed = image.buffer.clone();
            image.set_appended_signature(payload).unwrap();
            assert_eq!(image.buffer, signed); // Includes stacked trailers in the prefix.
            image.remove_appended_signature().unwrap();
            assert_eq!(image.buffer, original[..prefix]);
        }
        Err(_) => assert_eq!(image.buffer, original),
    }
    *image = ELF::from_buffer(original.clone()).unwrap();
    match image.remove_appended_signature() {
        Ok(_) => assert_eq!(image.buffer, original[..prefix]),
        Err(_) => assert_eq!(image.buffer, original),
    }
    *image = ELF::from_buffer(original.clone()).unwrap();
    assert!(image.set_appended_signature(&[]).is_err());
    assert_eq!(image.buffer, original);
}

fn macho_edits(image: &mut MachO, payload: &[u8]) {
    // FAT parsing selects a thin slice, so compare against that slice.
    let original = image.buffer.clone();
    let _ = image.code_signature();
    let _ = image.code_signature_data();
    if let Ok(Some(blob)) = image.code_signature_data() {
        if !blob.is_empty() && blob.len() <= 256 {
            let replacement: Vec<_> = (0..blob.len())
                .map(|i| payload[i % payload.len()])
                .collect();
            match image.write_code_signature(&replacement) {
                Ok(()) => {
                    let command = image.code_signature().unwrap().unwrap();
                    let start = command.dataoff.value as usize;
                    let end = start + replacement.len();
                    assert_eq!(image.code_signature_data().unwrap().unwrap(), replacement);
                    assert_eq!(image.buffer[..start], original[..start]);
                    assert_eq!(image.buffer[end..], original[end..]);
                }
                Err(_) => assert_eq!(image.buffer, original),
            }
            *image = MachO::from_buffer(original.clone()).unwrap();
        }
    }
    match image.write_code_signature(payload) {
        Ok(()) => {
            let command = image.code_signature().unwrap().unwrap();
            let start = command.dataoff.value as usize;
            let end = start + command.datasize.value as usize;
            assert_eq!(image.code_signature_data().unwrap().unwrap(), payload);
            assert_eq!(image.buffer[..start], original[..start]);
            assert_eq!(image.buffer[end..], original[end..]);
        }
        Err(_) => assert_eq!(image.buffer, original),
    }
    *image = MachO::from_buffer(original.clone()).unwrap();
    match image.reserve_code_signature(payload.len() as u32) {
        Ok(layout) => {
            let reserved = image.buffer.clone();
            let prefix = image.buffer[layout.signing_range.clone()].to_vec();
            assert_eq!(
                image.reserve_code_signature(payload.len() as u32).unwrap(),
                layout
            );
            assert_eq!(image.buffer, reserved);
            assert!(image.write_code_signature(&[]).is_err());
            assert_eq!(image.buffer, reserved);
            image.write_code_signature(payload).unwrap();
            assert_eq!(image.buffer[layout.signing_range], prefix);
            assert_eq!(image.code_signature_data().unwrap().unwrap(), payload);
            let installed = image.buffer.clone();
            if image
                .reserve_code_signature(payload.len() as u32 + 1)
                .is_err()
            {
                assert_eq!(image.buffer, installed);
            }
            image.remove_code_signature().unwrap();
            assert!(image.code_signature().unwrap().is_none());
        }
        Err(_) => assert_eq!(image.buffer, original),
    }
    *image = MachO::from_buffer(original.clone()).unwrap();
    match image.remove_code_signature() {
        Ok(()) => assert!(image.code_signature().unwrap().is_none()),
        Err(_) => assert_eq!(image.buffer, original),
    }
    *image = MachO::from_buffer(original.clone()).unwrap();
    assert!(image.reserve_code_signature(0).is_err());
    assert_eq!(image.buffer, original);
}

fn pe_image(target: pe::build::Target) -> PE {
    use pe::build::{ImageKind, PeBuilder, SectionSpec};
    let mut builder = PeBuilder::new(target, ImageKind::Executable);
    let code = builder
        .add_section(SectionSpec::new(".text", vec![0xc3], 0x60000020))
        .unwrap();
    let entry = builder.define_symbol(&code, 0).unwrap();
    builder.set_entry_point(&entry).unwrap();
    builder.build().unwrap()
}

fn macho_image(target: macho::build::Target) -> MachO {
    use macho::build::{MachOBuilder, SectionSpec, SegmentSpec, Version};
    let mut builder = MachOBuilder::new(
        target,
        Version {
            major: 13,
            minor: 0,
            patch: 0,
        },
    );
    builder.enable_dyld().unwrap();
    let text = builder.add_segment(SegmentSpec::new("__TEXT", 5)).unwrap();
    let code = builder
        .add_section(&text, SectionSpec::new("__text", vec![0; 16]))
        .unwrap();
    builder.set_entry(&code, 0).unwrap();
    builder.add_symbol("_main", &code, 0).unwrap();
    builder.build().unwrap()
}

fn append_trailer(buffer: &mut Vec<u8>, payload: &[u8]) {
    buffer.extend_from_slice(payload);
    buffer.extend_from_slice(&[0, 0, 2, 0, 0, 0, 0, 0]);
    buffer.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buffer.extend_from_slice(elf::signature::MODULE_SIGNATURE_MARKER);
}

/// Deterministic signature-specific seeds, including valid, malformed and aliased containers.
/// These are generated from Rust builders or minimal headers; no external tools or keys.
pub fn signature_seeds() -> Vec<(String, Vec<u8>)> {
    let mut seeds = Vec::new();
    for (name, target) in [
        ("pe32", pe::build::Target::X86),
        ("pe64", pe::build::Target::X64),
    ] {
        let mut image = pe_image(target);
        seeds.push((format!("signature-{name}-unsigned"), image.buffer.clone()));
        image.buffer.extend_from_slice(b"overlay");
        image
            .append_certificate(&CertificateOwned {
                revision: 0x1234,
                certificate_type: 0xabcd,
                data: vec![1, 2, 3],
                padding: vec![0x7a; 5],
            })
            .unwrap();
        image
            .append_certificate(&CertificateOwned::pkcs_signed_data(vec![0x55; 17]))
            .unwrap();
        let table = image.certificates().unwrap().unwrap();
        let start = table.offset;
        let slot = &image.optional_header.data_directories[pe::header::SECURITY];
        seeds.push((format!("signature-{name}-records"), image.buffer.clone()));
        for kind in [
            "short-record",
            "overflow-record",
            "unaligned",
            "zero-size",
            "post-overlay",
            "section-alias",
            "relocation-alias",
            "coff-alias",
            "debug-alias",
            "missing-slot",
        ] {
            let mut bytes = image.buffer.clone();
            match kind {
                "short-record" => bytes[start..start + 4].copy_from_slice(&7u32.to_le_bytes()),
                "overflow-record" => {
                    bytes[start..start + 4].copy_from_slice(&u32::MAX.to_le_bytes())
                }
                "unaligned" => ByteOrder::Little.write_u32(
                    &mut bytes,
                    slot.virtual_address.offset,
                    start as u32 + 1,
                ),
                "zero-size" => ByteOrder::Little.write_u32(&mut bytes, slot.size.offset, 0),
                "post-overlay" => bytes.push(1),
                "section-alias" => ByteOrder::Little.write_u32(
                    &mut bytes,
                    image.sections[0].pointer_to_raw_data.offset,
                    start as u32,
                ),
                "relocation-alias" => {
                    ByteOrder::Little.write_u32(
                        &mut bytes,
                        image.sections[0].pointer_to_relocations.offset,
                        start as u32,
                    );
                    ByteOrder::Little.write_u16(
                        &mut bytes,
                        image.sections[0].number_of_relocations.offset,
                        1,
                    );
                }
                "coff-alias" => ByteOrder::Little.write_u32(
                    &mut bytes,
                    image.coff_header.pointer_to_symbol_table.offset,
                    start as u32,
                ),
                "debug-alias" => {
                    let raw = image.sections[0].pointer_to_raw_data.value as usize;
                    bytes[raw..raw + 28].fill(0);
                    ByteOrder::Little.write_u32(&mut bytes, raw + 16, 8);
                    ByteOrder::Little.write_u32(&mut bytes, raw + 24, start as u32);
                    let debug = &image.optional_header.data_directories[pe::header::DEBUG];
                    ByteOrder::Little.write_u32(
                        &mut bytes,
                        debug.virtual_address.offset,
                        image.sections[0].virtual_address.value,
                    );
                    ByteOrder::Little.write_u32(&mut bytes, debug.size.offset, 28);
                }
                "missing-slot" => ByteOrder::Little.write_u32(
                    &mut bytes,
                    image.optional_header.number_of_rva_and_sizes.offset,
                    4,
                ),
                _ => unreachable!(),
            }
            seeds.push((format!("signature-{name}-{kind}"), bytes));
        }
    }
    for (name, target) in [
        ("x64", macho::build::Target::X86_64),
        ("arm64", macho::build::Target::Arm64),
    ] {
        let mut image = macho_image(target);
        seeds.push((
            format!("signature-macho-{name}-unsigned"),
            image.buffer.clone(),
        ));
        let padding = 32 + image.header.sizeofcmds.value as usize;
        let entry = image
            .load_commands
            .iter()
            .find(|c| c.cmd.value == macho::load_command::LC_MAIN)
            .unwrap()
            .cmd
            .offset
            + 8;
        let mut bytes = image.buffer.clone();
        ByteOrder::Little.write_u64(&mut bytes, entry, padding as u64);
        seeds.push((format!("signature-macho-{name}-entry-padding"), bytes));
        let mut bytes = image.buffer.clone();
        bytes[padding] = 1;
        seeds.push((format!("signature-macho-{name}-occupied-padding"), bytes));
        image.reserve_code_signature(32).unwrap();
        image.write_code_signature(&[0x5a; 32]).unwrap();
        let command = image
            .load_commands
            .iter()
            .find(|c| c.cmd.value == LC_CODE_SIGNATURE)
            .unwrap()
            .cmd
            .offset;
        let start = image.code_signature().unwrap().unwrap().dataoff.value;
        seeds.push((
            format!("signature-macho-{name}-signed"),
            image.buffer.clone(),
        ));
        for kind in [
            "overflow",
            "unaligned",
            "header-alias",
            "section-alias",
            "duplicate",
            "bad-command-size",
            "empty",
            "post-overlay",
            "mapping-alias",
            "unknown-command",
        ] {
            let mut bytes = image.buffer.clone();
            match kind {
                "overflow" => ByteOrder::Little.write_u32(&mut bytes, command + 12, u32::MAX),
                "unaligned" => {
                    ByteOrder::Little.write_u32(&mut bytes, command + 8, start + 1);
                    ByteOrder::Little.write_u32(&mut bytes, command + 12, 31);
                }
                "header-alias" => ByteOrder::Little.write_u32(&mut bytes, command + 8, 32),
                "section-alias" => {
                    if let macho::section::SectionEntry::Section64(s) = &image.sections[0] {
                        ByteOrder::Little.write_u32(&mut bytes, s.offset.offset, start);
                    }
                }
                "duplicate" => {
                    let end = 32 + image.header.sizeofcmds.value as usize;
                    bytes.copy_within(command..command + 16, end);
                    ByteOrder::Little.write_u32(&mut bytes, 16, image.header.ncmds.value + 1);
                    ByteOrder::Little.write_u32(&mut bytes, 20, image.header.sizeofcmds.value + 16);
                }
                "bad-command-size" => ByteOrder::Little.write_u32(&mut bytes, command + 4, 8),
                "empty" => ByteOrder::Little.write_u32(&mut bytes, command + 12, 0),
                "post-overlay" => bytes.push(1),
                "mapping-alias" => {
                    let segment = &image.segments[1];
                    if let macho::segment::SegmentEntry::Segment64(s) = segment {
                        ByteOrder::Little.write_u64(
                            &mut bytes,
                            s.filesize.offset,
                            image.buffer.len() as u64,
                        );
                        ByteOrder::Little.write_u64(
                            &mut bytes,
                            s.vmsize.offset,
                            image.buffer.len() as u64,
                        );
                    }
                }
                "unknown-command" => ByteOrder::Little.write_u32(&mut bytes, entry - 8, 0x7777),
                _ => unreachable!(),
            }
            seeds.push((format!("signature-macho-{name}-{kind}"), bytes));
        }
    }
    // Read-only signature access also supports 32-bit and big-endian Mach-O.
    for (endian, order) in [(1, ByteOrder::Little), (2, ByteOrder::Big)] {
        for class in [1, 2] {
            let header = if class == 1 { 28 } else { 32 };
            let mut bytes = vec![0; header + 16 + 8];
            order.write_u32(
                &mut bytes,
                0,
                if class == 1 { 0xfeedface } else { 0xfeedfacf },
            );
            order.write_u32(&mut bytes, 4, 7);
            order.write_u32(&mut bytes, 12, 1);
            order.write_u32(&mut bytes, 16, 1);
            order.write_u32(&mut bytes, 20, 16);
            order.write_u32(&mut bytes, header, LC_CODE_SIGNATURE);
            order.write_u32(&mut bytes, header + 4, 16);
            order.write_u32(&mut bytes, header + 8, (header + 16) as u32);
            order.write_u32(&mut bytes, header + 12, 8);
            seeds.push((format!("signature-macho-read-{class}-{endian}"), bytes));
        }
    }
    for (name, bytes) in crate::synthetic_seeds()
        .into_iter()
        .filter(|(n, _)| n.starts_with("elf"))
    {
        let mut signed = bytes.clone();
        append_trailer(&mut signed, b"inner");
        seeds.push((format!("signature-{name}-single"), signed.clone()));
        let mut stacked = signed.clone();
        append_trailer(&mut stacked, b"outer");
        seeds.push((format!("signature-{name}-stacked"), stacked));
        let info = signed.len() - 40;
        for index in 0..8 {
            let mut invalid = signed.clone();
            invalid[info + index] = 0xff;
            seeds.push((format!("signature-{name}-metadata-{index}"), invalid));
        }
        for length in [0, u32::MAX] {
            let mut invalid = signed.clone();
            ByteOrder::Big.write_u32(&mut invalid, info + 8, length);
            seeds.push((format!("signature-{name}-length-{length}"), invalid));
        }
        let mut alias = signed.clone();
        let image = ELF::from_buffer(bytes.clone()).unwrap();
        image.byte_order().unwrap().write_u16(
            &mut alias,
            image.header.eh_size.offset,
            signed.len() as u16,
        );
        seeds.push((format!("signature-{name}-header-alias"), alias));
        signed.pop();
        seeds.push((format!("signature-{name}-partial-marker"), signed));
        let mut truncated = bytes;
        truncated.extend_from_slice(elf::signature::MODULE_SIGNATURE_MARKER);
        seeds.push((format!("signature-{name}-truncated-info"), truncated));

        // File-backed sections/programs and both header tables must stay outside the trailer.
        use elf::build::layout::{serialize_layout, HeaderSpec, ProgramSpec, SectionHeaderSpec};
        let order = image.byte_order().unwrap();
        let layout = serialize_layout(
            HeaderSpec {
                class: image.header.class().unwrap(),
                byte_order: order,
                os_abi: 0,
                image_type: 2,
                machine: if image.header.class().unwrap() == elf::header::ElfClass::Elf32 {
                    3
                } else {
                    62
                },
                entry: 0,
                flags: 0,
                section_names: 0,
            },
            &[0; 128],
            &[ProgramSpec {
                kind: 1,
                offset: 96,
                file_size: 16,
                memory_size: 16,
                alignment: 1,
                ..Default::default()
            }],
            &[SectionHeaderSpec {
                kind: elf::section::SHT_PROGBITS,
                offset: 96,
                size: 16,
                ..Default::default()
            }],
        )
        .unwrap();
        let prefix = layout.buffer.len();
        for kind in [
            "section-alias",
            "program-alias",
            "section-table-alias",
            "program-table-alias",
        ] {
            let mut alias = ELF::from_buffer(layout.buffer.clone()).unwrap();
            append_trailer(&mut alias.buffer, b"signature");
            match kind {
                "section-alias" => alias.section_headers[1]
                    .sh_offset_mut()
                    .update_with(&mut alias.buffer, prefix as u64, order)
                    .unwrap(),
                "program-alias" => alias.program_headers[0]
                    .p_offset_mut()
                    .update_with(&mut alias.buffer, prefix as u64, order)
                    .unwrap(),
                "section-table-alias" => alias
                    .header
                    .sh_off
                    .update_with(&mut alias.buffer, prefix as u64, order)
                    .unwrap(),
                "program-table-alias" => alias
                    .header
                    .ph_off
                    .update_with(&mut alias.buffer, prefix as u64, order)
                    .unwrap(),
                _ => unreachable!(),
            }
            seeds.push((format!("signature-{name}-{kind}"), alias.buffer));
        }
    }
    seeds.push((
        "signature-elf-marker-only".into(),
        elf::signature::MODULE_SIGNATURE_MARKER.to_vec(),
    ));
    seeds
}

pub(super) fn generation(data: &[u8]) {
    let selector = data.first().copied().unwrap_or(0);
    let payload = if data.is_empty() {
        &[0][..]
    } else {
        &data[..data.len().min(256)]
    };
    let mut pe = pe_image(if selector & 1 == 0 {
        pe::build::Target::X86
    } else {
        pe::build::Target::X64
    });
    pe_edits(&mut pe, payload);
    let mut macho = macho_image(if selector & 1 == 0 {
        macho::build::Target::X86_64
    } else {
        macho::build::Target::Arm64
    });
    macho_edits(&mut macho, payload);
    // Stacked trailers must retain the entire inner container during replacement.
    let mut bytes = crate::synthetic_seeds()
        .remove(usize::from(selector % 4) * 3)
        .1;
    append_trailer(&mut bytes, payload);
    append_trailer(&mut bytes, payload);
    elf_edits(&mut ELF::from_buffer(bytes).unwrap(), payload);
}
