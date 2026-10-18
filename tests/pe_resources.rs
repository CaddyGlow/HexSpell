#![cfg(all(feature = "pe", feature = "write"))]

use hexspell::pe::{
    resource::{
        icon::{Icon, IconImage},
        strings::StringTable,
        version::VersionBlock,
        *,
    },
    PE,
};
fn data(bytes: &[u8]) -> ResourceNode {
    ResourceNode::Data(ResourceData {
        bytes: bytes.to_vec(),
        code_page: 65001,
        reserved: 7,
    })
}

#[test]
fn resource_edit_rejects_directory_slots_outside_optional_header() {
    use hexspell::pe::build::{ImageKind, PeBuilder, SectionSpec, Target};
    for (target, base) in [(Target::X86, 96), (Target::X64, 112)] {
        let mut builder = PeBuilder::new(target, ImageKind::Dll);
        builder
            .add_section(SectionSpec::new(".text", vec![0xc3; 32], 0x60000020))
            .unwrap();
        let mut pe = builder.build().unwrap();
        let optional = pe.optional_header.magic.offset;
        let section = pe.sections[0].name.offset;
        pe.buffer
            .copy_within(section..section + 40, optional + base);
        pe.coff_header
            .size_of_optional_header
            .update(&mut pe.buffer, base as u16)
            .unwrap();
        pe.optional_header
            .number_of_rva_and_sizes
            .update(&mut pe.buffer, 3)
            .unwrap();
        let mut pe = PE::from_buffer(pe.buffer).unwrap();
        let before = pe.buffer.clone();
        assert!(pe
            .replace_resources(&OwnedResources::default(), SignaturePolicy::PreserveBytes)
            .is_err());
        assert_eq!(pe.buffer, before);
    }
}

#[test]
fn resource_edit_grows_a_valid_optional_header_without_directory_slots() {
    use hexspell::pe::build::{ImageKind, PeBuilder, SectionSpec, Target};
    for (target, base) in [(Target::X86, 96), (Target::X64, 112)] {
        let mut builder = PeBuilder::new(target, ImageKind::Dll);
        builder
            .add_section(SectionSpec::new(".text", vec![0xc3; 32], 0x60000020))
            .unwrap();
        let mut pe = builder.build().unwrap();
        let optional = pe.optional_header.magic.offset;
        let section = pe.sections[0].name.offset;
        pe.buffer
            .copy_within(section..section + 40, optional + base);
        pe.coff_header
            .size_of_optional_header
            .update(&mut pe.buffer, base as u16)
            .unwrap();
        pe.optional_header
            .number_of_rva_and_sizes
            .update(&mut pe.buffer, 0)
            .unwrap();
        let mut pe = PE::from_buffer(pe.buffer).unwrap();
        let resources = OwnedResources::default();
        pe.replace_resources(&resources, SignaturePolicy::PreserveBytes)
            .unwrap();
        let reparsed = PE::from_buffer(pe.buffer.clone()).unwrap();
        assert_eq!(reparsed.owned_resources().unwrap(), resources);
        assert_eq!(reparsed.sections[0].size_of_raw_data.value, 512);
        assert_eq!(reparsed.sections[0].virtual_address.value, 0x1000);
    }
}

#[test]
fn resource_edit_rejects_overflowing_virtual_extent_without_mutation() {
    use hexspell::pe::build::{ImageKind, PeBuilder, SectionSpec, Target};
    let mut builder = PeBuilder::new(Target::X64, ImageKind::Dll);
    let mut section = SectionSpec::new(".text", vec![0xc3], 0x60000020);
    section.virtual_size = 0xffffc000;
    builder.add_section(section).unwrap();
    let mut pe = builder.build().unwrap();
    let mut resources = OwnedResources::default();
    resources
        .insert(&[ResourceKey::Id(1)], data(&vec![0; 0x4000]))
        .unwrap();
    let before = pe.buffer.clone();
    assert!(pe
        .replace_resources(&resources, SignaturePolicy::PreserveBytes)
        .is_err());
    assert_eq!(pe.buffer, before);
}
#[test]
fn resource_serialization_preserves_metadata_names_and_payloads() {
    let mut tree = OwnedResources {
        characteristics: 12,
        time_date_stamp: 34,
        major_version: 5,
        minor_version: 6,
        ..Default::default()
    };
    tree.insert(&[ResourceKey::Id(0x123456)], data(b"abc"))
        .unwrap();
    tree.insert(&[ResourceKey::Name(vec![0xd800, 65])], data(b"opaque"))
        .unwrap();
    let bytes = tree.serialize(0x1000).unwrap();
    let parsed = ResourceTree::parse(&bytes, 0, |r| Ok((r - 0x1000) as usize)).unwrap();
    assert_eq!(parsed.root.header.characteristics.value, 12);
    assert_eq!(parsed.root.entries.len(), 2);
    match &parsed.root.entries[0] {
        ResourceEntry::Data { entry, data, .. } => {
            assert_eq!(entry.name_utf16(&bytes, 0).unwrap(), vec![0xd800, 65]);
            let offset = (data.offset_to_data.value - 0x1000) as usize;
            assert_eq!(&bytes[offset..offset + data.size.value as usize], b"opaque");
        }
        _ => panic!(),
    };
    assert_eq!(tree.serialize(0x1000).unwrap(), bytes);
}
#[test]
fn resource_paths_reject_collisions_without_mutation() {
    let mut tree = OwnedResources::default();
    tree.insert(&[ResourceKey::Id(1)], data(b"one")).unwrap();
    tree.insert(&[ResourceKey::Id(2)], data(b"two")).unwrap();
    let before = tree.clone();
    assert!(tree
        .rename(&[ResourceKey::Id(1)], ResourceKey::Id(2))
        .is_err());
    assert_eq!(before, tree);
    assert!(tree.insert(&[ResourceKey::Id(1)], data(b"bad")).is_err());
    assert_eq!(before, tree);
    assert!(tree.remove(&[ResourceKey::Id(1)]).is_ok());
}
#[test]
fn resource_edit_roundtrip_and_failure_atomicity() {
    for sample in [
        &include_bytes!("samples/sample1.exe")[..],
        &include_bytes!("samples/sample64.exe")[..],
    ] {
        let mut pe = PE::from_buffer(sample.to_vec()).unwrap();
        let mut tree = OwnedResources::default();
        tree.insert(&[ResourceKey::Id(10)], data(b"sentinel"))
            .unwrap();
        let rvas: Vec<_> = pe
            .sections
            .iter()
            .map(|s| s.virtual_address.value)
            .collect();
        let report = pe
            .replace_resources(&tree, SignaturePolicy::PreserveBytes)
            .unwrap();
        assert_eq!(report.signature, SignatureOutcome::Unsigned);
        assert_eq!(pe.owned_resources().unwrap(), tree);
        assert_eq!(
            rvas,
            pe.sections[..rvas.len()]
                .iter()
                .map(|s| s.virtual_address.value)
                .collect::<Vec<_>>()
        );
        let before = pe.buffer.clone();
        tree.entries.push(tree.entries[0].clone());
        assert!(pe
            .replace_resources(&tree, SignaturePolicy::PreserveBytes)
            .is_err());
        assert_eq!(before, pe.buffer);
    }
}
#[test]
fn string_blocks_roundtrip_raw_surrogates_and_boundaries() {
    let mut table = StringTable::default();
    table.slots[15] = vec![0xd800, 0, 0xdc00];
    let bytes = table.serialize().unwrap();
    assert_eq!(StringTable::parse(&bytes).unwrap(), table);
    assert_eq!(StringTable::location(15).unwrap(), (1, 15));
    assert_eq!(StringTable::location(16).unwrap(), (2, 0));
    assert!(StringTable::parse(&bytes[..bytes.len() - 1]).is_err());
}
#[test]
fn version_blocks_preserve_unknown_children() {
    let root = VersionBlock {
        key: "VS_VERSION_INFO".encode_utf16().collect(),
        value_type: 0,
        value: vec![1, 2, 3],
        children: vec![VersionBlock {
            key: vec![0xd800],
            value_type: 1,
            value: vec![65, 0, 0, 0],
            children: vec![],
        }],
    };
    let bytes = root.serialize().unwrap();
    assert_eq!(VersionBlock::parse(&bytes).unwrap(), root);
    assert!(VersionBlock::parse(&bytes[..bytes.len() - 1]).is_err());
    let empty = VersionBlock {
        key: vec![65],
        value_type: 0,
        value: vec![],
        children: vec![],
    };
    assert_eq!(
        VersionBlock::parse(&empty.serialize().unwrap()).unwrap(),
        empty
    );
}
#[test]
fn icons_preserve_png_and_dib_bytes() {
    let ico = Icon {
        images: vec![
            IconImage {
                width: 16,
                height: 16,
                color_count: 0,
                reserved: 0,
                planes: 1,
                bit_count: 32,
                bytes: b"\x89PNGopaque".to_vec(),
            },
            IconImage {
                width: 32,
                height: 32,
                color_count: 0,
                reserved: 0,
                planes: 1,
                bit_count: 24,
                bytes: vec![40, 0, 0, 0],
            },
        ],
    };
    let bytes = ico.serialize().unwrap();
    assert_eq!(Icon::parse(&bytes).unwrap(), ico);
    assert_eq!(ico.group(&[1, 2]).unwrap().len(), 34);
    assert!(ico.group(&[1]).is_err());
    assert!(Icon::parse(&bytes[..bytes.len() - 1]).is_err());
}
#[test]
fn manifest_is_opaque_and_utf8_checked() {
    assert!(Manifest(vec![0xff]).utf8().is_err());
    assert_eq!(
        Manifest::from_utf8("<assembly/> ").utf8().unwrap(),
        "<assembly/> "
    );
}
#[test]
fn resource_parser_rejects_name_tags_and_truncation() {
    let mut bytes = vec![0u8; 32];
    bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
    bytes[16..20].copy_from_slice(&24u32.to_le_bytes());
    assert!(ResourceTree::parse(&bytes, 0, |r| Ok(r as usize)).is_err());
    bytes[16..20].copy_from_slice(&0x8000_0018u32.to_le_bytes());
    bytes[24..26].copy_from_slice(&20u16.to_le_bytes());
    assert!(ResourceTree::parse(&bytes, 0, |r| Ok(r as usize)).is_err());
}
#[test]
fn icons_update_atomically_with_unused_ids_and_language() {
    let icon = Icon {
        images: vec![IconImage {
            width: 16,
            height: 16,
            color_count: 0,
            reserved: 0,
            planes: 1,
            bit_count: 32,
            bytes: vec![1, 2, 3],
        }],
    };
    let mut tree = OwnedResources::default();
    let name = ResourceKey::Id(1);
    assert_eq!(tree.set_icon(name.clone(), 1033, &icon).unwrap(), vec![1]);
    assert_eq!(tree.icon(&name, 1033).unwrap(), icon);
    assert_eq!(tree.set_icon(name.clone(), 1041, &icon).unwrap(), vec![2]);
    assert_eq!(tree.icon(&name, 1033).unwrap(), icon);
    assert_eq!(tree.icon(&name, 1041).unwrap(), icon);
    let before = tree.clone();
    let bad = Icon {
        images: vec![icon.images[0].clone(); 65536],
    };
    assert!(tree.set_icon(name, 1033, &bad).is_err());
    assert_eq!(before, tree);
}
#[test]
fn edit_certificate_policy_retains_overlay_and_reports_invalidation() {
    let sample = include_bytes!("samples/sample1.exe");
    for policy in [SignaturePolicy::PreserveBytes, SignaturePolicy::Strip] {
        let mut pe = PE::from_buffer(sample.to_vec()).unwrap();
        let start = (pe.buffer.len() + 7) & !7;
        pe.buffer.resize(start, 0);
        pe.buffer.extend_from_slice(&[8, 0, 0, 0, 0, 2, 2, 0]);
        pe.buffer.extend_from_slice(b"OVERLAY_SENTINEL");
        let d = &mut pe.optional_header.data_directories[hexspell::pe::header::SECURITY];
        d.virtual_address
            .update(&mut pe.buffer, start as u32)
            .unwrap();
        d.size.update(&mut pe.buffer, 8).unwrap();
        let report = pe
            .replace_resources(&OwnedResources::default(), policy)
            .unwrap();
        assert!(pe.buffer.ends_with(b"OVERLAY_SENTINEL"));
        assert_eq!(
            report.signature,
            if policy == SignaturePolicy::Strip {
                SignatureOutcome::Stripped
            } else {
                SignatureOutcome::Invalidated
            }
        );
        if policy == SignaturePolicy::Strip {
            assert_eq!(
                pe.optional_header.data_directories[hexspell::pe::header::SECURITY]
                    .size
                    .value,
                0
            );
        } else {
            let d = &pe.optional_header.data_directories[hexspell::pe::header::SECURITY];
            assert_eq!(
                &pe.buffer[d.virtual_address.value as usize..d.virtual_address.value as usize + 8],
                &[8, 0, 0, 0, 0, 2, 2, 0]
            );
        }
    }
}
#[test]
fn checked_payload_rejects_crossing_raw_section_extent() {
    let pe = PE::from_buffer(include_bytes!("samples/sample1.exe").to_vec()).unwrap();
    let section = &pe.sections[0];
    let mut raw = vec![0; 16];
    raw[..4].copy_from_slice(
        &(section.virtual_address.value + section.size_of_raw_data.value - 1).to_le_bytes(),
    );
    raw[4..8].copy_from_slice(&2u32.to_le_bytes());
    let entry = ResourceDataEntry::parse(&raw, 0).unwrap();
    assert!(entry.payload(&pe).is_err());
}
#[test]
fn resource_names_after_odd_payload_remain_aligned() {
    let mut tree = OwnedResources::default();
    tree.entries.push((ResourceKey::from("a"), data(b"x")));
    tree.entries.push((ResourceKey::from("b"), data(b"y")));
    let bytes = tree.serialize(4096).unwrap();
    let parsed = ResourceTree::parse(&bytes, 0, |_| Ok(0)).unwrap();
    for entry in parsed.root.entries {
        if let ResourceEntry::Data { entry, .. } = entry {
            assert_eq!(entry.name_or_id.value & 1, 0);
        }
    }
}
#[test]
fn language_string_update_preserves_neighbors() {
    let mut tree = OwnedResources::default();
    tree.set_string(15, 1033, vec![65]).unwrap();
    tree.set_string(14, 1033, vec![66]).unwrap();
    tree.set_string(15, 1041, vec![0xd800]).unwrap();
    assert_eq!(tree.string(15, 1033).unwrap(), Some(vec![65]));
    assert_eq!(tree.string(14, 1033).unwrap(), Some(vec![66]));
    assert_eq!(tree.string(15, 1041).unwrap(), Some(vec![0xd800]));
    assert_eq!(tree.string(16, 1033).unwrap(), None);
    let before = tree.clone();
    assert!(tree.set_string(15, 1033, vec![65; 65536]).is_err());
    assert_eq!(tree, before);
}
#[test]
fn certificate_aliases_and_resource_metadata_extents_are_rejected() {
    let mut pe = PE::from_buffer(include_bytes!("samples/sample1.exe").to_vec()).unwrap();
    let mut tree = OwnedResources::default();
    tree.insert(&[ResourceKey::Id(1)], data(b"x")).unwrap();
    pe.replace_resources(&tree, SignaturePolicy::PreserveBytes)
        .unwrap();
    let last = pe.sections.last().unwrap();
    let invalid_size = last.size_of_raw_data.value + 1;
    pe.optional_header.data_directories[hexspell::pe::header::RESOURCE]
        .size
        .update(&mut pe.buffer, invalid_size)
        .unwrap();
    assert!(pe.owned_resources().is_err());
    for policy in [SignaturePolicy::PreserveBytes, SignaturePolicy::Strip] {
        let mut pe = PE::from_buffer(include_bytes!("samples/sample1.exe").to_vec()).unwrap();
        let raw = pe.sections[0].pointer_to_raw_data.value;
        let d = &mut pe.optional_header.data_directories[hexspell::pe::header::SECURITY];
        d.virtual_address.update(&mut pe.buffer, raw).unwrap();
        d.size.update(&mut pe.buffer, 8).unwrap();
        let before = pe.buffer.clone();
        assert!(pe
            .replace_resources(&OwnedResources::default(), policy)
            .is_err());
        assert_eq!(pe.buffer, before);
    }
}
#[test]
fn stripping_certificate_rejects_coff_string_table_alias() {
    let mut pe = PE::from_buffer(include_bytes!("samples/sample1.exe").to_vec()).unwrap();
    let symbols = pe.buffer.len();
    pe.buffer.extend_from_slice(&[0; 18]);
    let strings = pe.buffer.len();
    pe.buffer.extend_from_slice(&20u32.to_le_bytes());
    let cert = (pe.buffer.len() + 7) & !7;
    pe.buffer.resize(cert, 0);
    pe.buffer.extend_from_slice(&[8, 0, 0, 0, 0, 2, 2, 0]);
    pe.buffer.resize(strings + 20, 0);
    pe.coff_header
        .pointer_to_symbol_table
        .update(&mut pe.buffer, symbols as u32)
        .unwrap();
    pe.coff_header
        .number_of_symbols
        .update(&mut pe.buffer, 1)
        .unwrap();
    let d = &mut pe.optional_header.data_directories[hexspell::pe::header::SECURITY];
    d.virtual_address
        .update(&mut pe.buffer, cert as u32)
        .unwrap();
    d.size.update(&mut pe.buffer, 8).unwrap();
    let before = pe.buffer.clone();
    assert!(pe
        .replace_resources(&OwnedResources::default(), SignaturePolicy::Strip)
        .is_err());
    assert_eq!(before, pe.buffer);
}
#[test]
fn resource_parser_bounds_acyclic_shared_child_expansion() {
    // Each directory has two distinct IDs pointing at the same next directory.
    // The file stores only nine nodes, but naive recursive expansion creates
    // 511 nodes. No ancestor repeats, so cycle/depth checks cannot bound work.
    const LEVELS: usize = 8;
    let mut bytes = vec![0u8; LEVELS * 32 + 16];
    for level in 0..LEVELS {
        let start = level * 32;
        bytes[start + 14..start + 16].copy_from_slice(&2u16.to_le_bytes());
        for entry in 0..2 {
            let pos = start + 16 + entry * 8;
            bytes[pos..pos + 4].copy_from_slice(&(entry as u32 + 1).to_le_bytes());
            let child = 0x8000_0000 | ((level + 1) * 32) as u32;
            bytes[pos + 4..pos + 8].copy_from_slice(&child.to_le_bytes());
        }
    }
    assert!(matches!(
        ResourceTree::parse(&bytes, 0, |_| unreachable!("no data leaves")),
        Err(hexspell::errors::FileParseError::InvalidFileFormat)
    ));
}
