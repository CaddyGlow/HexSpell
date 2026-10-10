//! Differential checks use pefile's schema, not HexSpell's offsets as expectations.

use hexspell::field::{Field, FixedBytes};
use hexspell::pe::{
    self,
    header::{ImageBase, PEType, SizedU64},
    PE,
};

use super::pefile_report;

#[path = "synthetic.rs"]
mod synthetic;

trait OracleValue {
    fn oracle_value(&self) -> String;
}

macro_rules! numeric_value {
    ($($ty:ty),*) => { $(impl OracleValue for $ty {
        fn oracle_value(&self) -> String { self.to_string() }
    })* };
}
numeric_value!(u8, u16, u32, u64, i16);

impl OracleValue for ImageBase {
    fn oracle_value(&self) -> String {
        match self {
            Self::Base32(v) => v.to_string(),
            Self::Base64(v) => v.to_string(),
        }
    }
}
impl OracleValue for SizedU64 {
    fn oracle_value(&self) -> String {
        match self {
            Self::U32(v) => v.to_string(),
            Self::U64(v) => v.to_string(),
        }
    }
}
impl<const N: usize> OracleValue for FixedBytes<N> {
    fn oracle_value(&self) -> String {
        hex(&self.0)
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn check<T: OracleValue>(report: &toml::Value, key: &str, field: &Field<T>) {
    let expected = report
        .get(key)
        .unwrap_or_else(|| panic!("missing oracle field {key}"));
    assert_eq!(
        field.value.oracle_value(),
        expected["value"].as_str().unwrap(),
        "{key}: value"
    );
    assert_eq!(
        field.offset,
        expected["offset"].as_integer().unwrap() as usize,
        "{key}: offset"
    );
    assert_eq!(
        field.size,
        expected["size"].as_integer().unwrap() as usize,
        "{key}: width"
    );
}

macro_rules! fields {
    ($report:expr, $prefix:expr, $record:expr, {$($field:ident => $sdk:literal),* $(,)?}) => {
        $(check($report, &format!("{}.{}", $prefix, $sdk), &$record.$field);)*
    };
}

fn image_report(pe: &PE) -> toml::Value {
    let report = pefile_report(&pe.buffer, "pefile_oracle.py", &["image"]);
    check_headers(pe, &report);
    assert_eq!(
        report["section_count"]["value"].as_str().unwrap(),
        pe.sections.len().to_string()
    );
    assert_eq!(
        report["checksum"]["value"].as_str().unwrap(),
        pe.calc_checksum().to_string()
    );
    for (index, section) in pe.sections.iter().enumerate() {
        fields!(&report, format!("section{index}"), section, {
            name => "Name", virtual_size => "Misc_VirtualSize", virtual_address => "VirtualAddress",
            size_of_raw_data => "SizeOfRawData", pointer_to_raw_data => "PointerToRawData",
            pointer_to_relocations => "PointerToRelocations", pointer_to_linenumbers => "PointerToLinenumbers",
            number_of_relocations => "NumberOfRelocations", number_of_linenumbers => "NumberOfLinenumbers",
            characteristics => "Characteristics",
        });
        assert_eq!(
            report[format!("payload{index}")]["value"].as_str().unwrap(),
            hex(pe.section_data(index).unwrap()),
            "section {index}: payload"
        );
        if section.size_of_raw_data.value > 0 {
            assert_eq!(
                report[format!("mapping{index}")]["value"].as_str().unwrap(),
                pe.rva_to_offset(section.virtual_address.value)
                    .unwrap()
                    .to_string()
            );
        }
    }
    report
}

fn record_report(buffer: &[u8], format: &str, offset: usize) -> toml::Value {
    pefile_report(
        buffer,
        "pefile_oracle.py",
        &[
            "record",
            "--format",
            format,
            "--offset",
            &offset.to_string(),
        ],
    )
}

fn patterned_buffer(offset: usize, size: usize, seed: u8) -> Vec<u8> {
    (0..offset + size)
        .map(|i| (i as u8).wrapping_mul(73).wrapping_add(seed))
        .collect()
}

fn check_headers(pe: &PE, report: &toml::Value) {
    // Header mappings are explicit SDK names; no offsets are copied from HexSpell.
    fields!(report, "coff", pe.coff_header, {
        machine => "Machine", number_of_sections => "NumberOfSections", time_date_stamp => "TimeDateStamp",
        pointer_to_symbol_table => "PointerToSymbolTable", number_of_symbols => "NumberOfSymbols",
        size_of_optional_header => "SizeOfOptionalHeader", characteristics => "Characteristics",
    });
    fields!(report, "optional", pe.optional_header, {
        magic => "Magic", major_linker_version => "MajorLinkerVersion", minor_linker_version => "MinorLinkerVersion",
        size_of_code => "SizeOfCode", size_of_initialized_data => "SizeOfInitializedData", size_of_uninitialized_data => "SizeOfUninitializedData",
        entry_point => "AddressOfEntryPoint", base_of_code => "BaseOfCode", image_base => "ImageBase",
        section_alignment => "SectionAlignment", file_alignment => "FileAlignment",
        major_operating_system_version => "MajorOperatingSystemVersion", minor_operating_system_version => "MinorOperatingSystemVersion",
        major_image_version => "MajorImageVersion", minor_image_version => "MinorImageVersion",
        major_subsystem_version => "MajorSubsystemVersion", minor_subsystem_version => "MinorSubsystemVersion",
        win32_version_value => "Reserved1", size_of_image => "SizeOfImage", size_of_headers => "SizeOfHeaders",
        checksum => "CheckSum", subsystem => "Subsystem", dll_characteristics => "DllCharacteristics",
        size_of_stack_reserve => "SizeOfStackReserve", size_of_stack_commit => "SizeOfStackCommit",
        size_of_heap_reserve => "SizeOfHeapReserve", size_of_heap_commit => "SizeOfHeapCommit",
        loader_flags => "LoaderFlags", number_of_rva_and_sizes => "NumberOfRvaAndSizes",
    });
    if let Some(field) = &pe.optional_header.base_of_data {
        check(report, "optional.BaseOfData", field);
    } else {
        assert!(report.get("optional.BaseOfData").is_none());
    }
    for (index, directory) in pe
        .optional_header
        .data_directories
        .iter()
        .take(pe.optional_header.active_data_directory_count())
        .enumerate()
    {
        fields!(report, format!("directory{index}"), directory, {virtual_address => "VirtualAddress", size => "Size"});
    }
    fields!(report, "dos", pe.dos_header, {
        e_magic => "e_magic", e_cblp => "e_cblp", e_cp => "e_cp", e_crlc => "e_crlc",
        e_cparhdr => "e_cparhdr", e_minalloc => "e_minalloc", e_maxalloc => "e_maxalloc",
        e_ss => "e_ss", e_sp => "e_sp", e_csum => "e_csum", e_ip => "e_ip", e_cs => "e_cs",
        e_lfarlc => "e_lfarlc", e_ovno => "e_ovno", e_oemid => "e_oemid", e_oeminfo => "e_oeminfo",
        e_lfanew => "e_lfanew", e_res0 => "e_res[0]", e_res1 => "e_res[1]", e_res2 => "e_res[2]", e_res3 => "e_res[3]",
        e_res2_0 => "e_res2[0]", e_res2_1 => "e_res2[1]", e_res2_2 => "e_res2[2]", e_res2_3 => "e_res2[3]",
        e_res2_4 => "e_res2[4]", e_res2_5 => "e_res2[5]", e_res2_6 => "e_res2[6]", e_res2_7 => "e_res2[7]",
        e_res2_8 => "e_res2[8]", e_res2_9 => "e_res2[9]",
    });
}

const FIXTURES: &[&[u8]] = &[
    include_bytes!("../samples/sample1.exe"),
    include_bytes!("../samples/sample2.dll"),
    include_bytes!("../samples/sample64.exe"),
];

#[test]
#[ignore = "requires Python pefile; run explicitly in CI"]
fn all_image_header_fields_match_pefile() {
    for bytes in FIXTURES {
        image_report(&PE::from_buffer(bytes.to_vec()).unwrap());
    }
    for is_64 in [false, true] {
        image_report(&PE::from_buffer(synthetic::image(is_64)).unwrap());
    }
}

#[test]
#[ignore = "requires Python pefile; run explicitly in CI"]
fn checksums_large_odd_and_even_images_match_pefile() {
    for length in [65535, 65536, 65537, 1048579] {
        let mut buffer = synthetic::image(true);
        buffer.extend(
            (buffer.len()..length).map(|index| (index as u8).wrapping_mul(197).wrapping_add(41)),
        );
        image_report(&PE::from_buffer(buffer).unwrap());
    }
}

fn assert_payloads(pe: &PE, expected: &[Vec<u8>]) {
    image_report(pe);
    assert_eq!(pe.sections.len(), expected.len());
    for (index, (actual, expected)) in payloads(pe).iter().zip(expected).enumerate() {
        assert_eq!(
            actual, expected,
            "section {index}: original payload must survive the edit"
        );
    }
}

fn payloads(pe: &PE) -> Vec<Vec<u8>> {
    let mut payloads: Vec<_> = (0..pe.sections.len())
        .map(|index| pe.section_data(index).unwrap().to_vec())
        .collect();
    // Only debug file-pointer fixups are normalized. All other bytes must
    // survive exactly, and the referenced debug payload is checked separately.
    if let Some(debug) = pe.debug_directory().unwrap() {
        for entry in debug.entries {
            for (section, payload) in pe.sections.iter().zip(&mut payloads) {
                if let Some(relative) = entry
                    .pointer_to_raw_data
                    .offset
                    .checked_sub(section.pointer_to_raw_data.value as usize)
                {
                    if let Some(field) = payload.get_mut(relative..relative + 4) {
                        field.fill(0);
                    }
                }
            }
        }
    }
    payloads
}

fn debug_payloads(pe: &PE) -> Vec<Vec<u8>> {
    pe.debug_directory()
        .unwrap()
        .map(|debug| {
            debug
                .entries
                .into_iter()
                .map(|entry| entry.raw_data(&pe.buffer).unwrap().to_vec())
                .collect()
        })
        .unwrap_or_default()
}

fn assert_layout(pe: &PE) {
    let file_alignment = pe.optional_header.file_alignment.value;
    let section_alignment = pe.optional_header.section_alignment.value;
    assert_eq!(pe.optional_header.size_of_headers.value % file_alignment, 0);
    let mut raw_end = pe.optional_header.size_of_headers.value;
    let mut virtual_end = section_alignment;
    for section in &pe.sections {
        assert_eq!(section.virtual_address.value % section_alignment, 0);
        assert!(section.virtual_address.value >= virtual_end);
        virtual_end = section.virtual_address.value
            + section
                .virtual_size
                .value
                .max(section.size_of_raw_data.value);
        if section.size_of_raw_data.value > 0 {
            assert_eq!(section.pointer_to_raw_data.value % file_alignment, 0);
            assert_eq!(section.size_of_raw_data.value % file_alignment, 0);
            assert!(section.pointer_to_raw_data.value >= raw_end);
            raw_end = section.pointer_to_raw_data.value + section.size_of_raw_data.value;
            assert!(raw_end as usize <= pe.buffer.len());
        }
    }
    assert!(pe.optional_header.size_of_image.value >= virtual_end);
    assert_eq!(
        pe.optional_header.size_of_image.value % section_alignment,
        0
    );
    assert_eq!(pe.optional_header.checksum.value, pe.calc_checksum());
}

#[test]
#[ignore = "requires Python pefile; run explicitly in CI"]
fn created_images_and_section_insertion_match_pefile() {
    for is_64 in [false, true] {
        for length in [0, 1, 511, 512, 513, 8193] {
            let mut pe = PE::from_buffer(synthetic::image(is_64)).unwrap();
            let mut expected = payloads(&pe);
            let data: Vec<u8> = (0..length)
                .map(|index| (index as u8).wrapping_mul(53).wrapping_add(11))
                .collect();
            let section = pe
                .insert_section(pe::section::NewSection {
                    name: ".newdata".into(),
                    data: data.clone(),
                    characteristics: pe::section::READ | pe::section::INITIALIZED_DATA,
                })
                .unwrap();
            let mut padded = data;
            padded.resize(section.size_of_raw_data.value as usize, 0);
            expected.push(padded);
            assert_payloads(&pe, &expected);
            assert_layout(&pe);
            assert_eq!(pe.sections.last().unwrap().name_str(), ".newdata");
        }
    }
}

#[test]
#[ignore = "requires Python pefile; run explicitly in CI"]
fn remove_first_middle_last_sections_matches_pefile() {
    for is_64 in [false, true] {
        for index in 0..3 {
            let mut pe = PE::from_buffer(synthetic::image(is_64)).unwrap();
            let mut expected = payloads(&pe);
            expected.remove(index);
            pe.remove_section(index).unwrap();
            assert_payloads(&pe, &expected);
            assert_layout(&pe);
        }
    }
}

#[test]
#[ignore = "requires Python pefile; run explicitly in CI"]
fn optional_header_growth_matches_pefile() {
    for is_64 in [false, true] {
        for extra in [0, 16, 512, 1024] {
            let mut pe = PE::from_buffer(synthetic::image(is_64)).unwrap();
            let expected = payloads(&pe);
            pe.grow_optional_header(extra).unwrap();
            pe.sync_layout().unwrap();
            assert_payloads(&pe, &expected);
            assert_layout(&pe);
        }
    }
}

#[test]
#[ignore = "requires Python pefile; run explicitly in CI"]
fn rename_patch_and_sync_match_pefile() {
    for bytes in FIXTURES
        .iter()
        .map(|bytes| bytes.to_vec())
        .chain([synthetic::image(false), synthetic::image(true)])
    {
        let mut pe = PE::from_buffer(bytes).unwrap();
        let expected = payloads(&pe);
        for name in ["", ".x", "12345678"] {
            pe.rename_section(0, name).unwrap();
            pe.optional_header
                .entry_point
                .update(&mut pe.buffer, pe.sections[0].virtual_address.value + 7)
                .unwrap();
            pe.optional_header
                .dll_characteristics
                .update(&mut pe.buffer, 0x0140)
                .unwrap();
            pe.optional_header
                .major_image_version
                .update(&mut pe.buffer, 0x1234)
                .unwrap();
            pe.sync_layout().unwrap();
            assert_payloads(&pe, &expected);
            assert_layout(&pe);
        }
    }
}

#[test]
#[ignore = "requires Python pefile; run explicitly in CI"]
fn directory_record_fields_match_pefile() {
    for offset in [0, 17, 512] {
        for seed in [0, 0x5a, 0xff] {
            let buffer = patterned_buffer(offset, 320, seed);
            check_fixed_records(&buffer, offset);
            for (kind, tls_format, load_format) in [
                (
                    PEType::PE32,
                    "IMAGE_TLS_DIRECTORY",
                    "IMAGE_LOAD_CONFIG_DIRECTORY",
                ),
                (
                    PEType::PE32Plus,
                    "IMAGE_TLS_DIRECTORY64",
                    "IMAGE_LOAD_CONFIG_DIRECTORY64",
                ),
            ] {
                let tls = pe::tls::TlsDirectory::parse(&buffer, offset, kind).unwrap();
                let report = record_report(&buffer, tls_format, offset);
                fields!(&report, "record", tls, {
                    start_address_of_raw_data => "StartAddressOfRawData", end_address_of_raw_data => "EndAddressOfRawData",
                    address_of_index => "AddressOfIndex", address_of_callbacks => "AddressOfCallBacks",
                    size_of_zero_fill => "SizeOfZeroFill", characteristics => "Characteristics",
                });
                let mut load_buffer = buffer.clone();
                load_buffer[offset..offset + 4].copy_from_slice(&320u32.to_le_bytes());
                let load = pe::load_config::LoadConfigDirectory::parse(&load_buffer, offset, kind)
                    .unwrap();
                let report = record_report(&load_buffer, load_format, offset);
                check_load_config(&load, &report, kind);
            }
        }
    }
}

fn check_load_config(
    load: &pe::load_config::LoadConfigDirectory,
    report: &toml::Value,
    kind: PEType,
) {
    fields!(report, "record", load, {
        size => "Size", time_date_stamp => "TimeDateStamp", major_version => "MajorVersion", minor_version => "MinorVersion",
        global_flags_clear => "GlobalFlagsClear", global_flags_set => "GlobalFlagsSet", critical_section_default_timeout => "CriticalSectionDefaultTimeout",
        de_commit_free_block_threshold => "DeCommitFreeBlockThreshold", de_commit_total_free_threshold => "DeCommitTotalFreeThreshold",
        lock_prefix_table => "LockPrefixTable", maximum_allocation_size => "MaximumAllocationSize", virtual_memory_threshold => "VirtualMemoryThreshold",
        process_heap_flags => "ProcessHeapFlags", csd_version => "CSDVersion", reserved1 => "DependentLoadFlags", security_cookie => "SecurityCookie",
    });
    check(
        report,
        "record.ProcessAffinityMask",
        load.process_affinity_mask
            .as_ref()
            .expect("affinity is present in both layouts"),
    );
    check(
        report,
        if matches!(kind, PEType::PE32) {
            "record.EditList"
        } else {
            "record.EditList.low32"
        },
        &load.reserved2,
    );
}

fn check_fixed_records(buffer: &[u8], offset: usize) {
    check_sdk_records(buffer, offset);
    let section = pe::section::PeSection::parse_section(buffer, offset).unwrap();
    let report = record_report(buffer, "IMAGE_SECTION_HEADER", offset);
    fields!(&report, "record", section, {
        name => "Name", virtual_size => "Misc_VirtualSize", virtual_address => "VirtualAddress", size_of_raw_data => "SizeOfRawData",
        pointer_to_raw_data => "PointerToRawData", pointer_to_relocations => "PointerToRelocations", pointer_to_linenumbers => "PointerToLinenumbers",
        number_of_relocations => "NumberOfRelocations", number_of_linenumbers => "NumberOfLinenumbers", characteristics => "Characteristics",
    });
    let debug = pe::debug::DebugDirectoryEntry::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "IMAGE_DEBUG_DIRECTORY", offset);
    fields!(&report, "record", debug, {
        characteristics => "Characteristics", time_date_stamp => "TimeDateStamp", major_version => "MajorVersion", minor_version => "MinorVersion",
        debug_type => "Type", size_of_data => "SizeOfData", address_of_raw_data => "AddressOfRawData", pointer_to_raw_data => "PointerToRawData",
    });
    let runtime = pe::exception::RuntimeFunction::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "RUNTIME_FUNCTION", offset);
    fields!(&report, "record", runtime, {begin_address => "BeginAddress", end_address => "EndAddress", unwind_data => "UnwindData"});
    let export = pe::export::ExportDirectory::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "IMAGE_EXPORT_DIRECTORY", offset);
    fields!(&report, "record", export, {
        characteristics => "Characteristics", time_date_stamp => "TimeDateStamp", major_version => "MajorVersion", minor_version => "MinorVersion",
        name => "Name", base => "Base", number_of_functions => "NumberOfFunctions", number_of_names => "NumberOfNames",
        address_of_functions => "AddressOfFunctions", address_of_names => "AddressOfNames", address_of_name_ordinals => "AddressOfNameOrdinals",
    });
    let import = pe::import::ImageImportDescriptor::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "IMAGE_IMPORT_DESCRIPTOR", offset);
    fields!(&report, "record", import, { original_first_thunk => "OriginalFirstThunk", time_date_stamp => "TimeDateStamp", forwarder_chain => "ForwarderChain", name => "Name", first_thunk => "FirstThunk" });
    let delay = pe::delay::DelayLoadDescriptor::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "IMAGE_DELAY_IMPORT_DESCRIPTOR", offset);
    fields!(&report, "record", delay, {
        attributes => "grAttrs", dll_name_rva => "szName", module_handle_rva => "phmod", delay_import_address_table_rva => "pIAT",
        delay_import_name_table_rva => "pINT", bound_delay_import_table_rva => "pBoundIAT", unload_delay_import_table_rva => "pUnloadIAT", time_date_stamp => "dwTimeStamp",
    });
    let bound = pe::bound::BoundImportDescriptor::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "IMAGE_BOUND_IMPORT_DESCRIPTOR", offset);
    fields!(&report, "record", bound, {time_date_stamp => "TimeDateStamp", offset_module_name => "OffsetModuleName", number_of_module_forwarder_refs => "NumberOfModuleForwarderRefs"});
    let forwarder = pe::bound::BoundForwarderRef::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "IMAGE_BOUND_FORWARDER_REF", offset);
    fields!(&report, "record", forwarder, {time_date_stamp => "TimeDateStamp", offset_module_name => "OffsetModuleName", reserved => "Reserved"});
    let resource = pe::resource::ResourceDirectory::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "IMAGE_RESOURCE_DIRECTORY", offset);
    fields!(&report, "record", resource, {characteristics => "Characteristics", time_date_stamp => "TimeDateStamp", major_version => "MajorVersion", minor_version => "MinorVersion", number_of_named_entries => "NumberOfNamedEntries", number_of_id_entries => "NumberOfIdEntries"});
    let entry = pe::resource::ResourceDirectoryEntry::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "IMAGE_RESOURCE_DIRECTORY_ENTRY", offset);
    fields!(&report, "record", entry, {name_or_id => "Name", offset_to_data => "OffsetToData"});
    let data = pe::resource::ResourceDataEntry::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "IMAGE_RESOURCE_DATA_ENTRY", offset);
    fields!(&report, "record", data, {offset_to_data => "OffsetToData", size => "Size", code_page => "CodePage", reserved => "Reserved"});
    let mut reloc_buffer = buffer.to_vec();
    reloc_buffer[offset + 4..offset + 8].copy_from_slice(&12u32.to_le_bytes());
    let block = pe::relocation::BaseRelocationBlock::parse(&reloc_buffer, offset).unwrap();
    let report = record_report(&reloc_buffer, "IMAGE_BASE_RELOCATION", offset);
    fields!(&report, "record", block, {page_rva => "VirtualAddress", block_size => "SizeOfBlock"});
    for entry in &block.entries {
        let report = record_report(
            &reloc_buffer,
            "IMAGE_BASE_RELOCATION_ENTRY",
            entry.raw.offset,
        );
        check(&report, "record.Data", &entry.raw);
    }
}

#[test]
#[ignore = "requires Python pefile; run explicitly in CI"]
fn patched_header_sentinels_match_pefile() {
    macro_rules! patch {
        ($pe:ident, $group:ident, $start:expr, {$($field:ident),* $(,)?}) => {
            let mut values = ($start..).step_by(3);
            $($pe.$group.$field.update(&mut $pe.buffer, values.next().unwrap()).unwrap();)*
        };
    }
    for is_64 in [false, true] {
        let mut pe = PE::from_buffer(synthetic::image(is_64)).unwrap();
        patch!(pe, dos_header, 0x1201u16, {
            e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno,
            e_res0, e_res1, e_res2, e_res3, e_oemid, e_oeminfo, e_res2_0, e_res2_1, e_res2_2, e_res2_3, e_res2_4, e_res2_5, e_res2_6, e_res2_7, e_res2_8, e_res2_9,
        });
        patch!(pe, optional_header, 0x3401u16, {
            major_operating_system_version, minor_operating_system_version, major_image_version, minor_image_version,
            major_subsystem_version, minor_subsystem_version, dll_characteristics,
        });
        patch!(pe, optional_header, 17u8, {major_linker_version, minor_linker_version});
        patch!(pe, optional_header, 0x1234_5601u32, {
            size_of_code, size_of_initialized_data, size_of_uninitialized_data, win32_version_value, loader_flags,
        });
        pe.coff_header
            .time_date_stamp
            .update(&mut pe.buffer, 0x8765_4321)
            .unwrap();
        pe.optional_header
            .image_base
            .update(
                &mut pe.buffer,
                if is_64 {
                    ImageBase::Base64(0x1234_5678_0000)
                } else {
                    ImageBase::Base32(0x1200_0000)
                },
            )
            .unwrap();
        for (index, field) in [
            &mut pe.optional_header.size_of_stack_reserve,
            &mut pe.optional_header.size_of_stack_commit,
            &mut pe.optional_header.size_of_heap_reserve,
            &mut pe.optional_header.size_of_heap_commit,
        ]
        .into_iter()
        .enumerate()
        {
            let value = 0x1234_5000 + index as u32 * 0x1000;
            field
                .update(
                    &mut pe.buffer,
                    if is_64 {
                        SizedU64::U64(0x9876_0000_0000 + value as u64)
                    } else {
                        SizedU64::U32(value)
                    },
                )
                .unwrap();
        }
        pe.sync_layout().unwrap();
        image_report(&PE::from_buffer(pe.buffer).unwrap());
    }
}

#[test]
#[ignore = "requires Python pefile; run explicitly in CI"]
fn serialized_created_and_edited_images_match_pefile() {
    for is_64 in [false, true] {
        let mut pe = PE::from_buffer(synthetic::image(is_64)).unwrap();
        pe.insert_section(pe::section::NewSection {
            name: ".saved".into(),
            data: vec![0x6b; 513],
            characteristics: pe::section::READ,
        })
        .unwrap();
        pe.rename_section(0, ".code").unwrap();
        pe.grow_optional_header(16).unwrap();
        let path = std::env::temp_dir().join(format!(
            "hexspell-pefile-{}-{is_64}.exe",
            std::process::id()
        ));
        pe.write_file(path.to_str().unwrap()).unwrap();
        let saved = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(saved, pe.buffer);
        let reparsed = PE::from_buffer(saved).unwrap();
        image_report(&reparsed);
        assert_layout(&reparsed);
    }
}

fn check_sdk_records(buffer: &[u8], offset: usize) {
    let symbol = pe::symbol::ImageSymbol::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "SDK_IMAGE_SYMBOL", offset);
    fields!(&report, "record", symbol, {short_name => "Name", value => "Value", section_number => "SectionNumber", sym_type => "Type", storage_class => "StorageClass", number_of_aux_symbols => "NumberOfAuxSymbols"});
    let reloc = pe::section_reloc::SectionRelocation::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "SDK_IMAGE_RELOCATION", offset);
    fields!(&report, "record", reloc, {virtual_address => "VirtualAddress", symbol_table_index => "SymbolTableIndex", reloc_type => "Type"});
    let line = pe::linenum::LineNumberEntry::parse(buffer, offset).unwrap();
    let report = record_report(buffer, "SDK_IMAGE_LINENUMBER", offset);
    fields!(&report, "record", line, {type_field => "Type", line_number => "Linenumber"});
    let mut certificate_buffer = buffer.to_vec();
    certificate_buffer[offset..offset + 4].copy_from_slice(&24u32.to_le_bytes());
    let certificate = pe::certificate::WinCertificate::parse(&certificate_buffer, offset).unwrap();
    let report = record_report(&certificate_buffer, "SDK_WIN_CERTIFICATE", offset);
    fields!(&report, "record", certificate, {length => "dwLength", revision => "wRevision", certificate_type => "wCertificateType"});
    let mut clr_buffer = buffer.to_vec();
    clr_buffer[offset..offset + 4].copy_from_slice(&72u32.to_le_bytes());
    let clr = pe::clr::Cor20Header::parse(&clr_buffer, offset).unwrap();
    let report = record_report(&clr_buffer, "SDK_COR20_HEADER", offset);
    fields!(&report, "record", clr, {cb => "cb", major_runtime_version => "MajorRuntimeVersion", minor_runtime_version => "MinorRuntimeVersion", flags => "Flags", entry_point_token => "EntryPointToken"});
    for (directory, name) in [
        (&clr.metadata, "MetaData"),
        (&clr.resources, "Resources"),
        (&clr.strong_name_signature, "StrongNameSignature"),
        (&clr.code_manager_table, "CodeManagerTable"),
        (&clr.vtable_fixups, "VTableFixups"),
        (&clr.export_address_table_jumps, "ExportAddressTableJumps"),
        (&clr.managed_native_header, "ManagedNativeHeader"),
    ] {
        check(
            &report,
            &format!("record.{name}RVA"),
            &directory.virtual_address,
        );
        check(&report, &format!("record.{name}Size"), &directory.size);
    }
}

fn check_resolved_directories(pe: &PE) {
    let report = pefile_report(&pe.buffer, "pefile_oracle.py", &["image", "--directories"]);
    let imports = pe.imports().unwrap();
    assert_eq!(
        report["import_count"]["value"].as_str().unwrap(),
        imports.dlls.len().to_string()
    );
    for (module_index, module) in imports.dlls.iter().enumerate() {
        let prefix = format!("import{module_index}");
        fields!(&report, format!("{prefix}.descriptor"), module.descriptor, {
            original_first_thunk => "OriginalFirstThunk", time_date_stamp => "TimeDateStamp", forwarder_chain => "ForwarderChain", name => "Name", first_thunk => "FirstThunk",
        });
        assert_eq!(
            report[format!("{prefix}.dll")]["value"].as_str().unwrap(),
            hex(module.dll_name.as_bytes())
        );
        assert_eq!(
            report[format!("{prefix}.count")]["value"].as_str().unwrap(),
            module.entries.len().to_string()
        );
        for (index, entry) in module.entries.iter().enumerate() {
            let thunk = match entry {
                pe::import::ImportEntry::ByName { by_name, thunk } => {
                    check(&report, &format!("{prefix}.hint{index}"), &by_name.hint);
                    assert_eq!(
                        report[format!("{prefix}.name{index}")]["value"]
                            .as_str()
                            .unwrap(),
                        hex(by_name.name.as_bytes())
                    );
                    assert_eq!(
                        report[format!("{prefix}.name{index}")]["offset"]
                            .as_integer()
                            .unwrap() as usize,
                        by_name.name_offset
                    );
                    thunk
                }
                pe::import::ImportEntry::Ordinal { ordinal, thunk } => {
                    assert_eq!(
                        report[format!("{prefix}.ordinal{index}")]["value"]
                            .as_str()
                            .unwrap(),
                        ordinal.to_string()
                    );
                    thunk
                }
            };
            match thunk {
                pe::import::ThunkSlot::U32(field) => check(
                    &report,
                    &format!("{prefix}.thunk{index}.AddressOfData"),
                    field,
                ),
                pe::import::ThunkSlot::U64(field) => check(
                    &report,
                    &format!("{prefix}.thunk{index}.AddressOfData"),
                    field,
                ),
            }
        }
    }
    let exports = pe.exports().unwrap();
    assert_eq!(
        report["has_exports"]["value"].as_str().unwrap(),
        u8::from(exports.is_some()).to_string()
    );
    if let Some(exports) = exports {
        fields!(&report, "export", exports.directory, {
            characteristics => "Characteristics", time_date_stamp => "TimeDateStamp", major_version => "MajorVersion", minor_version => "MinorVersion",
            name => "Name", base => "Base", number_of_functions => "NumberOfFunctions", number_of_names => "NumberOfNames",
            address_of_functions => "AddressOfFunctions", address_of_names => "AddressOfNames", address_of_name_ordinals => "AddressOfNameOrdinals",
        });
        assert_eq!(
            report["export.named_count"]["value"].as_str().unwrap(),
            exports.named.len().to_string()
        );
        for (index, entry) in exports.named.iter().enumerate() {
            assert_eq!(
                report[format!("export.name{index}")]["value"]
                    .as_str()
                    .unwrap(),
                hex(entry.name.as_bytes())
            );
            check(&report, &format!("export.name_rva{index}"), &entry.name_rva);
            check(
                &report,
                &format!("export.ordinal_index{index}"),
                &entry.name_ordinal_index,
            );
            check(
                &report,
                &format!("export.function{}", entry.name_ordinal_index.value),
                &entry.function_rva,
            );
        }
        for (index, function) in exports.functions.iter().enumerate() {
            let field = match function {
                pe::export::FunctionExport::Local { function_rva, .. }
                | pe::export::FunctionExport::Forwarder { function_rva, .. } => function_rva,
            };
            check(&report, &format!("export.function{index}"), field);
        }
    }
}

#[test]
#[ignore = "requires Python pefile; run explicitly in CI"]
fn hybrid_load_config_pointer_matches_pefile() {
    for (kind, format) in [
        (PEType::PE32, "IMAGE_LOAD_CONFIG_DIRECTORY"),
        (PEType::PE32Plus, "IMAGE_LOAD_CONFIG_DIRECTORY64"),
    ] {
        let buffer = patterned_buffer(17, 320, 0xa5);
        let report = record_report(&buffer, format, 17);
        for machine in [
            pe::arch_data::IMAGE_FILE_MACHINE_ARMNT,
            pe::arch_data::IMAGE_FILE_MACHINE_ARM64,
            pe::arch_data::IMAGE_FILE_MACHINE_ARM64X,
        ] {
            let fields =
                pe::arch_data::HybridLoadConfigFields::parse(&buffer, 17, 320, machine, kind)
                    .unwrap();
            check(
                &report,
                "record.CHPEMetadataPointer",
                fields.hybrid_metadata_pointer.as_ref().unwrap(),
            );
            assert!(fields.chpe_code_address_range_offset.is_none());
            assert!(fields.chpe_code_address_range_count.is_none());
        }
    }
}

#[test]
#[ignore = "requires Python pefile and HEXSPELL_PE_CORPUS; run explicitly in CI"]
fn corpus_creation_and_edits_match_pefile() {
    let directory = std::env::var_os("HEXSPELL_PE_CORPUS")
        .expect("set HEXSPELL_PE_CORPUS to build_corpus.py's output directory");
    let mut files: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "exe" || ext == "dll")
        })
        .collect();
    files.sort();
    assert!(!files.is_empty());
    for file in files {
        eprintln!("corpus oracle: {}", file.display());
        let mut pe = PE::from_buffer(std::fs::read(&file).unwrap()).unwrap();
        image_report(&pe);
        check_resolved_directories(&pe);
        let expected = payloads(&pe);
        let debug_data = debug_payloads(&pe);
        pe.rename_section(0, ".oracle").unwrap();
        pe.optional_header
            .major_image_version
            .update(&mut pe.buffer, 0x5678)
            .unwrap();
        pe.sync_layout().unwrap();
        assert_payloads(&pe, &expected);
        check_resolved_directories(&pe);
        // Adding/removing a fresh tail section must preserve all existing
        // directory references, symbol tables, and any trailing overlay.
        let old_overlay_start = pe
            .sections
            .iter()
            .map(|section| {
                section.pointer_to_raw_data.value as usize + section.size_of_raw_data.value as usize
            })
            .max()
            .unwrap();
        let overlay = pe.buffer[old_overlay_start..].to_vec();
        pe.insert_section(pe::section::NewSection {
            name: ".added".into(),
            data: vec![0x5a; 513],
            characteristics: pe::section::READ,
        })
        .unwrap();
        image_report(&pe);
        check_resolved_directories(&pe);
        assert_eq!(&payloads(&pe)[..expected.len()], expected);
        assert_eq!(debug_payloads(&pe), debug_data);
        assert!(
            pe.buffer.ends_with(&overlay),
            "insertion must preserve overlay"
        );
        pe.remove_section(pe.sections.len() - 1).unwrap();
        assert_payloads(&pe, &expected);
        check_resolved_directories(&pe);
        assert!(
            pe.buffer.ends_with(&overlay),
            "removal must preserve overlay"
        );
        assert_eq!(debug_payloads(&pe), debug_data);
        pe.grow_optional_header(16).unwrap();
        pe.sync_layout().unwrap();
        assert_payloads(&pe, &expected);
        check_resolved_directories(&pe);
        assert!(
            pe.buffer.ends_with(&overlay),
            "header growth must preserve overlay"
        );
        assert_eq!(debug_payloads(&pe), debug_data);
    }
}
