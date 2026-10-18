#![cfg(all(feature = "std", feature = "macho", feature = "common"))]

/// HexSpell Mach-O
/// ====================================
/// File to perform test on Mach-O parse
///
/// REFERENCES
/// -----------
/// Mach-O Structure    =>  https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format
/// Mach-O Viewer       =>  https://github.com/horsicq/XMachOViewer
///
use std::fs;
use toml::Value;

use hexspell::errors::FileParseError;
use hexspell::field::ByteOrder;
use hexspell::macho; // <-- Testing module

/// ============================================
/// Testing reading and parsing in a Mach-O file
/// ============================================
#[test]
fn test_macho_parse() {
    let toml_contents: String =
        fs::read_to_string("tests/tests.toml").expect("Failed to read tests.toml");
    let data: Value = toml::from_str(&toml_contents).expect("Failed to parse TOML");

    // MACHO FILES
    if let Some(elf) = data.get("macho").and_then(|v| v.as_table()) {
        for (key, value) in elf {
            let file_extension: &str = value
                .get("file_extension")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mut file_name: String = format!("tests/samples/{}", key);
            if !file_extension.is_empty() {
                file_name += &format!(".{}", file_extension);
            }

            // Getting real values from test.toml
            let macho_file: macho::MachO =
                macho::MachO::from_file(&file_name).expect("Error parsing MachO file");

            let magic = value
                .get("magic")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let cputype = value
                .get("cputype")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let cpusubtype = value
                .get("cpusubtype")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let filetype = value
                .get("filetype")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let ncmds = value
                .get("ncmds")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let sizeofcmds = value
                .get("sizeofcmds")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let flags = value
                .get("flags")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            // Testing parse params result
            assert_eq!(
                macho_file.header.magic.value, magic,
                "macho_file.header.magic doesnt match"
            );
            assert_eq!(
                macho_file.header.cpu_type.value, cputype,
                "macho_file.header.cpu_type doesnt match"
            );
            assert_eq!(
                macho_file.header.cpu_subtype.value, cpusubtype,
                "macho_file.header.cpu_subtype doesnt match"
            );
            assert_eq!(
                macho_file.header.file_type.value, filetype,
                "macho_file.header.file_type doesnt match"
            );
            assert_eq!(
                macho_file.header.ncmds.value, ncmds,
                "macho_file.header.ncmds doesnt match"
            );
            assert_eq!(
                macho_file.header.sizeofcmds.value, sizeofcmds,
                "macho_file.header.sizeofcmds doesnt match"
            );
            assert_eq!(
                macho_file.header.flags.value, flags,
                "macho_file.header.flags doesnt match"
            );
        }
    }
}

/// 32-bit Mach-O must not expose a reserved field at offset 28
#[test]
fn test_macho_32bit_reserved_is_none() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    assert!(
        macho_file.header.reserved.is_none(),
        "32-bit Mach-O must not have a reserved field"
    );
}

/// 64-bit Mach-O must expose reserved at offset 28
#[test]
fn test_macho_64bit_reserved_is_some() {
    let buffer = vec![
        0xCF, 0xFA, 0xED, 0xFE, // magic (64-bit LE)
        0x07, 0x00, 0x00, 0x00, // cputype
        0x03, 0x00, 0x00, 0x00, // cpusubtype
        0x02, 0x00, 0x00, 0x00, // filetype
        0x00, 0x00, 0x00, 0x00, // ncmds
        0x00, 0x00, 0x00, 0x00, // sizeofcmds
        0x00, 0x00, 0x00, 0x00, // flags
        0x42, 0x00, 0x00, 0x00, // reserved
    ];
    let macho_file = macho::MachO::from_buffer(buffer.clone()).expect("64-bit parse failed");
    let reserved = macho_file
        .header
        .reserved
        .as_ref()
        .expect("64-bit Mach-O must have reserved");
    assert_eq!(reserved.value, 0x42);
    assert_eq!(reserved.offset, 28);
}

/// Parsing a buffer without a valid Mach-O magic number should fail
#[test]
fn test_macho_invalid_buffer() {
    let buffer = vec![0u8; 4];
    let result = macho::MachO::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::InvalidFileFormat)));
}

/// Parsing a little-endian Mach-O buffer should succeed
#[test]
fn test_macho_parse_little_endian() {
    let buffer = vec![
        0xCE, 0xFA, 0xED, 0xFE, // magic (little-endian)
        0x07, 0x00, 0x00, 0x00, // cputype
        0x03, 0x00, 0x00, 0x00, // cpusubtype
        0x02, 0x00, 0x00, 0x00, // filetype
        0x00, 0x00, 0x00, 0x00, // ncmds
        0x00, 0x00, 0x00, 0x00, // sizeofcmds
        0x00, 0x00, 0x00, 0x00, // flags
    ];
    let macho_file = macho::MachO::from_buffer(buffer).expect("Error parsing little-endian MachO");
    assert_eq!(macho_file.byte_order(), ByteOrder::Little);
    assert_eq!(macho_file.header.magic.value, 0xFEEDFACE);
    assert_eq!(macho_file.header.cpu_type.value, 0x00000007);
    assert_eq!(macho_file.header.cpu_subtype.value, 0x00000003);
}

/// Missing load commands in a little-endian Mach-O should error
#[test]
fn test_macho_little_endian_missing_load_commands() {
    let buffer = vec![
        0xCE, 0xFA, 0xED, 0xFE, // magic (little-endian)
        0x07, 0x00, 0x00, 0x00, // cputype
        0x03, 0x00, 0x00, 0x00, // cpusubtype
        0x02, 0x00, 0x00, 0x00, // filetype
        0x01, 0x00, 0x00, 0x00, // ncmds = 1
        0x08, 0x00, 0x00, 0x00, // sizeofcmds = 8
        0x00, 0x00, 0x00, 0x00, // flags
    ];
    let result = macho::MachO::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::BufferOverflow)));
}

/// Parsing a big-endian Mach-O buffer should succeed
#[test]
fn test_macho_parse_big_endian() {
    let buffer = vec![
        0xFE, 0xED, 0xFA, 0xCE, // magic (big-endian)
        0x00, 0x00, 0x00, 0x07, // cputype
        0x00, 0x00, 0x00, 0x03, // cpusubtype
        0x00, 0x00, 0x00, 0x02, // filetype
        0x00, 0x00, 0x00, 0x00, // ncmds
        0x00, 0x00, 0x00, 0x00, // sizeofcmds
        0x00, 0x00, 0x00, 0x00, // flags
    ];
    let macho_file = macho::MachO::from_buffer(buffer).expect("Error parsing big-endian MachO");
    assert_eq!(macho_file.byte_order(), ByteOrder::Big);
    assert_eq!(macho_file.header.magic.value, 0xFEEDFACE);
    assert_eq!(macho_file.header.cpu_type.value, 0x00000007);
    assert_eq!(macho_file.header.cpu_subtype.value, 0x00000003);
}

/// Missing load commands in a big-endian Mach-O should error
#[test]
fn test_macho_big_endian_missing_load_commands() {
    let buffer = vec![
        0xFE, 0xED, 0xFA, 0xCE, // magic (big-endian)
        0x00, 0x00, 0x00, 0x07, // cputype
        0x00, 0x00, 0x00, 0x03, // cpusubtype
        0x00, 0x00, 0x00, 0x02, // filetype
        0x00, 0x00, 0x00, 0x01, // ncmds = 1
        0x00, 0x00, 0x00, 0x08, // sizeofcmds = 8
        0x00, 0x00, 0x00, 0x00, // flags
    ];
    let result = macho::MachO::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::BufferOverflow)));
}

/// Parsing a FAT Mach-O buffer should succeed
#[test]
fn test_macho_parse_fat() {
    let inner = vec![
        0xCE, 0xFA, 0xED, 0xFE, // magic (little-endian)
        0x07, 0x00, 0x00, 0x00, // cputype
        0x03, 0x00, 0x00, 0x00, // cpusubtype
        0x02, 0x00, 0x00, 0x00, // filetype
        0x00, 0x00, 0x00, 0x00, // ncmds
        0x00, 0x00, 0x00, 0x00, // sizeofcmds
        0x00, 0x00, 0x00, 0x00, // flags
    ];
    let offset = 0x20u32;
    let size = inner.len() as u32;
    let mut buffer = vec![
        0xCA, 0xFE, 0xBA, 0xBE, // FAT magic
        0x00, 0x00, 0x00, 0x01, // nfat_arch
        0x00, 0x00, 0x00, 0x07, // cputype
        0x00, 0x00, 0x00, 0x03, // cpusubtype
    ];
    buffer.extend_from_slice(&offset.to_be_bytes());
    buffer.extend_from_slice(&size.to_be_bytes());
    buffer.extend_from_slice(&0u32.to_be_bytes()); // align
    buffer.extend(vec![0u8; offset as usize - buffer.len()]);
    buffer.extend_from_slice(&inner);

    let macho_file = macho::MachO::from_buffer(buffer).expect("Error parsing FAT MachO");
    assert_eq!(macho_file.byte_order(), ByteOrder::Little);
    assert_eq!(macho_file.header.magic.value, 0xFEEDFACE);
}

/// Invalid offsets in a FAT Mach-O should error
#[test]
fn test_macho_fat_invalid_offset() {
    let mut buffer = vec![
        0xCA, 0xFE, 0xBA, 0xBE, // FAT magic
        0x00, 0x00, 0x00, 0x01, // nfat_arch
        0x00, 0x00, 0x00, 0x07, // cputype
        0x00, 0x00, 0x00, 0x03, // cpusubtype
    ];
    buffer.extend_from_slice(&0x40u32.to_be_bytes()); // offset beyond buffer
    buffer.extend_from_slice(&0x08u32.to_be_bytes()); // size
    buffer.extend_from_slice(&0u32.to_be_bytes()); // align

    let result = macho::MachO::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::BufferOverflow)));
}

/// Load command with cmdsize zero must not loop forever
#[test]
fn test_macho_cmdsize_zero_invalid() {
    let buffer = vec![
        0xCE, 0xFA, 0xED, 0xFE, // magic (little-endian 32-bit)
        0x07, 0x00, 0x00, 0x00, // cputype
        0x03, 0x00, 0x00, 0x00, // cpusubtype
        0x02, 0x00, 0x00, 0x00, // filetype
        0x01, 0x00, 0x00, 0x00, // ncmds = 1
        0x08, 0x00, 0x00, 0x00, // sizeofcmds = 8
        0x00, 0x00, 0x00, 0x00, // flags
        0x01, 0x00, 0x00, 0x00, // LC_SEGMENT cmd
        0x00, 0x00, 0x00, 0x00, // cmdsize = 0
    ];
    let result = macho::MachO::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::InvalidFileFormat)));
}

/// 32-bit LC_SEGMENT must use u32 layout for segment fields
#[test]
fn test_macho_segment_32bit_vmaddr() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    assert!(!macho_file.segments.is_empty());
    assert_eq!(macho_file.segments[0].name(), "__PAGEZERO");
    assert_eq!(macho_file.segments[0].vmaddr(), 0);
    assert_eq!(macho_file.segments[0].vmaddr_size(), 4);
}

/// Ensure writing a Mach-O file to disk succeeds and preserves contents
#[test]
fn test_macho_write_file() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    let tmp_path = std::env::temp_dir().join("macho_write_test");
    macho_file
        .write_file(tmp_path.to_str().unwrap())
        .expect("Error writing MachO to disk");

    let original = std::fs::read("tests/samples/machO-OSX-x86-ls")
        .expect("[!] Failed to read original MachO file");
    let written = std::fs::read(&tmp_path).expect("[!] Failed to read written MachO file");
    assert_eq!(original, written);

    std::fs::remove_file(tmp_path).expect("[!] Failed to remove written MachO file");
}

/// Writing a Mach-O file to a non-existent directory should fail
#[test]
fn test_macho_write_file_fail() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    let invalid_path = std::env::temp_dir()
        .join("nonexistent_dir")
        .join("macho.bin");
    let result = macho_file.write_file(invalid_path.to_str().unwrap());
    assert!(result.is_err());
}

/// Nested section records must be parsed from segment load commands (32-bit sample)
#[test]
fn test_macho_sections_parsed() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    // __TEXT has 5 sections, __DATA has 7 → 12 total.
    assert_eq!(macho_file.sections.len(), 12);
    let first = &macho_file.sections[0];
    assert_eq!(first.name(), "__text");
    assert_eq!(first.segment_name(), "__TEXT");
    assert_eq!(first.addr(), 5896);
    assert_eq!(first.size(), 15988);
    assert_eq!(first.offset(), 1800);
}

/// LC_SYMTAB symbols must resolve their names against the string table
#[test]
fn test_macho_symbols_parsed() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    let symbols = macho_file
        .symbols()
        .expect("symbol parse")
        .expect("sample has LC_SYMTAB");
    assert_eq!(symbols.symbols.len(), 86);
    // At least one symbol name should resolve to a non-empty C string.
    assert!(symbols.symbols.iter().any(|s| !s.name.is_empty()));
}

/// Linked dylibs must be listed with their resolved paths
#[test]
fn test_macho_linked_dylibs() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    let dylibs = macho_file.linked_dylibs().expect("dylib parse");
    assert_eq!(dylibs.len(), 3);
    assert!(dylibs.iter().any(|d| d == "/usr/lib/libSystem.B.dylib"));
    assert!(dylibs.iter().any(|d| d.contains("libncurses")));
}

/// Typed command iteration must expose the modeled load commands
#[test]
fn test_macho_typed_commands() {
    use macho::load_command::TypedCommand;
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    let typed = macho_file.typed_commands().expect("typed commands");

    let has_symtab = typed.iter().any(|c| matches!(c, TypedCommand::Symtab(_)));
    let has_dyld_info = typed.iter().any(|c| matches!(c, TypedCommand::DyldInfo(_)));
    let has_dylinker = typed.iter().any(|c| matches!(c, TypedCommand::Dylinker(_)));
    assert!(has_symtab, "expected an LC_SYMTAB typed command");
    assert!(has_dyld_info, "expected an LC_DYLD_INFO typed command");
    assert!(has_dylinker, "expected an LC_LOAD_DYLINKER typed command");

    for c in &typed {
        if let TypedCommand::Dylinker(s) = c {
            assert_eq!(s.name, "/usr/lib/dyld");
        }
    }
}

/// A thin Mach-O reports no FAT architectures
#[test]
fn test_macho_fat_architectures_thin() {
    let arches =
        macho::MachO::fat_architectures("tests/samples/machO-OSX-x86-ls").expect("fat query");
    assert!(arches.is_empty());
}

/// Typed section parsing for a hand-built 64-bit segment with one section_64
#[test]
fn test_macho_section_64_parsed() {
    let mut buffer = vec![0u8; 256];
    buffer[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes()); // 64-bit magic
    buffer[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds
    buffer[20..24].copy_from_slice(&(72u32 + 80u32).to_le_bytes()); // sizeofcmds
    let seg = 32usize;
    buffer[seg..seg + 4].copy_from_slice(&0x19u32.to_le_bytes()); // LC_SEGMENT_64
    buffer[seg + 4..seg + 8].copy_from_slice(&(72u32 + 80u32).to_le_bytes()); // cmdsize
    buffer[seg + 8..seg + 24].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    buffer[seg + 64..seg + 68].copy_from_slice(&1u32.to_le_bytes()); // nsects = 1

    let sect = seg + 72;
    buffer[sect..sect + 16].copy_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
    buffer[sect + 16..sect + 32].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    buffer[sect + 32..sect + 40].copy_from_slice(&0x1000u64.to_le_bytes()); // addr
    buffer[sect + 40..sect + 48].copy_from_slice(&0x40u64.to_le_bytes()); // size
    buffer[sect + 48..sect + 52].copy_from_slice(&0x200u32.to_le_bytes()); // offset

    let macho = macho::MachO::from_buffer(buffer).expect("parse macho");
    assert_eq!(macho.sections.len(), 1);
    assert_eq!(macho.sections[0].name(), "__text");
    assert_eq!(macho.sections[0].addr(), 0x1000);
    assert_eq!(macho.sections[0].size(), 0x40);
    assert_eq!(macho.sections[0].offset(), 0x200);
}

/// insert_segment appends LC when load-command region has room
#[test]
fn test_macho_insert_segment() {
    let mut buffer = vec![0u8; 256];
    // 64-bit Mach-O header (32 bytes)
    buffer[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
    buffer[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds
    buffer[20..24].copy_from_slice(&72u32.to_le_bytes()); // sizeofcmds (one LC_SEGMENT_64)
                                                          // LC_SEGMENT_64 at offset 32, cmdsize 72, fileoff 200
    buffer[32..36].copy_from_slice(&0x19u32.to_le_bytes());
    buffer[36..40].copy_from_slice(&72u32.to_le_bytes());
    buffer[32 + 8..32 + 24].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    buffer[32 + 40..32 + 48].copy_from_slice(&200u64.to_le_bytes()); // fileoff

    let mut macho = macho::MachO::from_buffer(buffer).expect("parse macho");
    assert_eq!(macho.segments.len(), 1);

    macho
        .insert_segment(macho::segment::NewSegment {
            name: "__DATA.inj".to_string(),
            data: vec![0x41, 0x42],
            initprot: macho::segment::prot::READ | macho::segment::prot::WRITE,
            maxprot: macho::segment::prot::READ | macho::segment::prot::WRITE,
        })
        .expect("insert_segment");

    assert_eq!(macho.segments.len(), 2);
    assert_eq!(macho.segments[1].name(), "__DATA.inj");
    assert_eq!(macho.segments[1].filesize(), 2);
}

/// Typed views for version / thread / linker / fileset load commands
#[test]
fn test_macho_extended_typed_commands() {
    use macho::load_command::{
        TypedCommand, LC_BUILD_VERSION, LC_FILESET_ENTRY, LC_LINKER_OPTION, LC_SOURCE_VERSION,
        LC_UNIXTHREAD, LC_VERSION_MIN_MACOSX,
    };

    let mut buffer = vec![0u8; 512];
    buffer[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
    buffer[16..20].copy_from_slice(&6u32.to_le_bytes()); // ncmds
    let mut off = 32usize;
    let write_lc = |buf: &mut Vec<u8>, at: usize, cmd: u32, size: u32| {
        buf[at..at + 4].copy_from_slice(&cmd.to_le_bytes());
        buf[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
    };

    write_lc(&mut buffer, off, LC_BUILD_VERSION, 24);
    buffer[off + 8..off + 12].copy_from_slice(&1u32.to_le_bytes()); // platform
    off += 24;

    write_lc(&mut buffer, off, LC_SOURCE_VERSION, 16);
    buffer[off + 8..off + 16].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
    off += 16;

    write_lc(&mut buffer, off, LC_VERSION_MIN_MACOSX, 16);
    buffer[off + 8..off + 12].copy_from_slice(&0x000A0B00u32.to_le_bytes());
    off += 16;

    write_lc(&mut buffer, off, LC_UNIXTHREAD, 24);
    buffer[off + 8..off + 12].copy_from_slice(&1u32.to_le_bytes()); // flavor
    buffer[off + 12..off + 16].copy_from_slice(&2u32.to_le_bytes()); // count
    buffer[off + 16..off + 24].copy_from_slice(&[0xAA; 8]);
    off += 24;

    write_lc(&mut buffer, off, LC_LINKER_OPTION, 24);
    buffer[off + 8..off + 12].copy_from_slice(&1u32.to_le_bytes());
    buffer[off + 12..off + 24].copy_from_slice(b"-dead_strip\0");
    off += 24;

    write_lc(&mut buffer, off, LC_FILESET_ENTRY, 48);
    buffer[off + 8..off + 16].copy_from_slice(&0x1000u64.to_le_bytes());
    buffer[off + 16..off + 24].copy_from_slice(&0x2000u64.to_le_bytes());
    buffer[off + 24..off + 28].copy_from_slice(&32u32.to_le_bytes());
    buffer[off + 32..off + 44].copy_from_slice(b"com.app.ext\0");
    off += 48;

    let sizeofcmds = (off - 32) as u32;
    buffer[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());

    let macho = macho::MachO::from_buffer(buffer).expect("parse");
    let typed = macho.typed_commands().expect("typed");

    assert!(typed
        .iter()
        .any(|c| matches!(c, TypedCommand::BuildVersion(_))));
    assert!(typed
        .iter()
        .any(|c| matches!(c, TypedCommand::SourceVersion(_))));
    assert!(typed
        .iter()
        .any(|c| matches!(c, TypedCommand::VersionMin(_))));
    assert!(typed
        .iter()
        .any(|c| matches!(c, TypedCommand::UnixThread(_))));
    assert!(typed
        .iter()
        .any(|c| matches!(c, TypedCommand::LinkerOption(_))));
    assert!(typed
        .iter()
        .any(|c| matches!(c, TypedCommand::FilesetEntry(_))));

    if let Some(TypedCommand::UnixThread(t)) = typed
        .iter()
        .find(|c| matches!(c, TypedCommand::UnixThread(_)))
    {
        assert_eq!(t.flavor.value, 1);
        assert_eq!(t.count.value, 2);
        assert_eq!(t.state.len(), 8);
    }
    if let Some(TypedCommand::LinkerOption(l)) = typed
        .iter()
        .find(|c| matches!(c, TypedCommand::LinkerOption(_)))
    {
        assert_eq!(l.options, vec!["-dead_strip".to_string()]);
    }
    if let Some(TypedCommand::FilesetEntry(f)) = typed
        .iter()
        .find(|c| matches!(c, TypedCommand::FilesetEntry(_)))
    {
        assert_eq!(f.entry_id, "com.app.ext");
        assert_eq!(f.vmaddr.value, 0x1000);
    }
}

/// Section relocation entries must parse as relocation_info
#[test]
fn test_macho_section_relocations() {
    use macho::relocation::RelocationEntry;

    let mut buffer = vec![0u8; 256];
    buffer[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
    buffer[16..20].copy_from_slice(&1u32.to_le_bytes());
    buffer[20..24].copy_from_slice(&(72u32 + 80u32).to_le_bytes());
    let seg = 32usize;
    buffer[seg..seg + 4].copy_from_slice(&0x19u32.to_le_bytes());
    buffer[seg + 4..seg + 8].copy_from_slice(&(72u32 + 80u32).to_le_bytes());
    buffer[seg + 8..seg + 24].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    buffer[seg + 64..seg + 68].copy_from_slice(&1u32.to_le_bytes());

    let sect = seg + 72;
    buffer[sect..sect + 16].copy_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
    buffer[sect + 16..sect + 32].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    buffer[sect + 56..sect + 60].copy_from_slice(&200u32.to_le_bytes()); // reloff
    buffer[sect + 60..sect + 64].copy_from_slice(&1u32.to_le_bytes()); // nreloc

    buffer[200..204].copy_from_slice(&16i32.to_le_bytes()); // r_address
    buffer[204..208].copy_from_slice(&0x1000_0001u32.to_le_bytes()); // sym=1, type=1

    let macho = macho::MachO::from_buffer(buffer).expect("parse");
    let relocs = macho.relocations().expect("relocs");
    assert_eq!(relocs.len(), 1);
    assert!(matches!(relocs[0].1[0], RelocationEntry::Regular(_)));
    if let RelocationEntry::Regular(r) = &relocs[0].1[0] {
        assert_eq!(r.r_address.value, 16);
        assert_eq!(r.r_symbolnum.value, 1);
        assert_eq!(r.r_type, 1);
    }
}

/// Export trie and bind opcode decoding
#[test]
fn test_macho_dyld_decode() {
    use macho::dyld::{decode_bind_opcodes, decode_export_trie, BindOpcode};

    // Minimal export trie: terminal node exporting "_main" at address 0x1000
    let export_trie = vec![
        0x03, // terminal size
        0x00, 0x80, 0x20, // flags=0, address uleb128=0x1000
        0x00, // no children
    ];
    let exports = decode_export_trie(&export_trie).expect("export trie");
    assert_eq!(exports.len(), 1);
    assert_eq!(exports[0].address, Some(0x1000));

    let bind = vec![0x90, 0x01, 0x20, 0xB0, 0x00]; // set seg 1 off 0x20, do bind, done
    let ops = decode_bind_opcodes(&bind).expect("bind");
    assert!(ops.iter().any(|o| matches!(o, BindOpcode::DoBind)));
}

/// FAT slice_ref avoids copying unrelated arch data; build and merge work
#[test]
fn test_macho_fat_slice_build_merge() {
    let thin_a = vec![
        0xCE, 0xFA, 0xED, 0xFE, 0x07, 0, 0, 0, 0x03, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];
    let thin_b = thin_a.clone();
    let arch_a = macho::fat::FatArch {
        cpu_type: 7,
        cpu_subtype: 3,
        offset: 0,
        size: 0,
        align: 12,
    };
    let arch_b = macho::fat::FatArch {
        cpu_type: 0x0100_000C,
        cpu_subtype: 0,
        offset: 0,
        size: 0,
        align: 12,
    };
    let fat = macho::fat::FatHeader::build(&[(arch_a, &thin_a), (arch_b, &thin_b)]).expect("build");
    assert_eq!(fat[0..4], [0xCA, 0xFE, 0xBA, 0xBE]);

    let slice = macho::MachO::fat_slice_ref(&fat, 1).expect("slice ref");
    assert_eq!(slice.len(), thin_b.len());

    let merged = macho::fat::FatHeader::merge(
        &fat,
        macho::fat::FatArch {
            cpu_type: 12,
            cpu_subtype: 0,
            offset: 0,
            size: 0,
            align: 12,
        },
        &thin_a,
    )
    .expect("merge");
    let header = macho::fat::FatHeader::parse(&merged)
        .expect("parse")
        .expect("fat");
    assert_eq!(header.arches.len(), 3);
}

/// insert_load_command_at, remove_load_command, add_section
#[test]
fn test_macho_structural_edits() {
    let mut buffer = vec![0u8; 512];
    buffer[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
    buffer[16..20].copy_from_slice(&1u32.to_le_bytes());
    buffer[20..24].copy_from_slice(&72u32.to_le_bytes());
    buffer[32..36].copy_from_slice(&0x19u32.to_le_bytes());
    buffer[36..40].copy_from_slice(&72u32.to_le_bytes());
    buffer[40..56].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    buffer[32 + 40..32 + 48].copy_from_slice(&300u64.to_le_bytes());

    let mut macho = macho::MachO::from_buffer(buffer).expect("parse");
    let ncmds_before = macho.header.ncmds.value;

    let uuid_lc = {
        let mut lc = vec![0u8; 24];
        lc[0..4].copy_from_slice(&0x1Bu32.to_le_bytes()); // LC_UUID
        lc[4..8].copy_from_slice(&24u32.to_le_bytes());
        lc[8..24].copy_from_slice(&[0x42u8; 16]);
        lc
    };
    macho
        .insert_load_command_at(0, &uuid_lc)
        .expect("insert lc");
    assert_eq!(macho.header.ncmds.value, ncmds_before + 1);

    macho.remove_load_command(0).expect("remove lc");
    assert_eq!(macho.header.ncmds.value, ncmds_before);

    macho
        .add_section(
            0,
            macho::section::NewSection {
                name: "__newsect".to_string(),
                addr: 0x2000,
                size: 0x10,
                offset: 0,
                align: 4,
                flags: 0,
            },
        )
        .expect("add section");
    assert_eq!(macho.sections.len(), 1);
    assert_eq!(macho.sections[0].name(), "__newsect");
}

/// __LLVM segment sections are discoverable
#[test]
fn test_macho_llvm_sections() {
    let mut buffer = vec![0u8; 512];
    buffer[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
    buffer[16..20].copy_from_slice(&1u32.to_le_bytes());
    buffer[20..24].copy_from_slice(&(72u32 + 80u32).to_le_bytes());
    let seg = 32usize;
    buffer[seg..seg + 4].copy_from_slice(&0x19u32.to_le_bytes());
    buffer[seg + 4..seg + 8].copy_from_slice(&(72u32 + 80u32).to_le_bytes());
    buffer[seg + 8..seg + 24].copy_from_slice(b"__LLVM\0\0\0\0\0\0\0\0\0\0");
    buffer[seg + 64..seg + 68].copy_from_slice(&1u32.to_le_bytes());
    let sect = seg + 72;
    buffer[sect..sect + 16].copy_from_slice(b"__bundle\0\0\0\0\0\0\0\0");
    buffer[sect + 16..sect + 32].copy_from_slice(b"__LLVM\0\0\0\0\0\0\0\0\0\0");

    let macho = macho::MachO::from_buffer(buffer).expect("parse");
    let llvm = macho.llvm_sections();
    assert_eq!(llvm.len(), 1);
    assert_eq!(llvm[0].name(), "__bundle");
}

#[test]
fn test_macho_export_trie_rejects_cycles_without_recursing() {
    // Root has one edge whose child offset points back to the root.
    let cyclic = [0, 1, b'a', 0, 0];
    assert!(matches!(
        macho::dyld::decode_export_trie(&cyclic),
        Err(hexspell::errors::FileParseError::InvalidFileFormat)
    ));
}

#[test]
fn export_trie_reads_nul_terminated_edges_and_rejects_truncation() {
    let trie = [0, 1, b'_', b'f', b'o', b'o', 0, 8, 2, 0, 42, 0];
    let exports = macho::dyld::decode_export_trie(&trie).unwrap();
    assert_eq!(exports[0].name, "_foo");
    assert_eq!(exports[0].address, Some(42));
    assert!(macho::dyld::decode_export_trie(&[0, 1, b'x']).is_err());
    assert!(macho::dyld::decode_export_trie(&[0, 1, b'x', 0, 99]).is_err());
}

#[test]
fn chained_pointer_words_decode_independent_bit_layouts() {
    use macho::dyld::{decode_chained_pointer, ChainedPointer};
    assert_eq!(
        decode_chained_pointer((1 << 63) | (3 << 51) | (255 << 24) | 12).unwrap(),
        ChainedPointer::Bind {
            ordinal: 12,
            addend: 255,
            next: 12
        }
    );
    assert_eq!(
        decode_chained_pointer((2 << 51) | (0xabu64 << 36) | 42).unwrap(),
        ChainedPointer::Rebase {
            target: 42,
            high8: 0xab,
            next: 8
        }
    );
    assert!(decode_chained_pointer((1 << 63) | (1 << 32)).is_err());
    assert!(decode_chained_pointer(1 << 44).is_err());
}

#[test]
fn chained_fixups_bound_repeated_import_names() {
    fn shared_name_blob(count: usize, length: usize) -> Vec<u8> {
        let names = 32 + count * 4;
        let mut bytes = vec![0; names + length + 1];
        for (at, value) in [(4, 28), (8, 32), (12, names), (16, count), (20, 1)] {
            bytes[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
        bytes[names..names + length].fill(b'x');
        bytes
    }
    let ordinary = macho::dyld::decode_chained_fixups(&shared_name_blob(16, 8)).unwrap();
    assert_eq!(ordinary.imports.len(), 16);
    assert!(ordinary.imports.iter().all(|i| i.name == "xxxxxxxx"));
    // All records alias one long string: 12 KiB must not allocate 8 MiB of names.
    assert!(macho::dyld::decode_chained_fixups(&shared_name_blob(1024, 8192)).is_err());
}

#[test]
fn chained_fixups_bound_aliased_page_tables() {
    let count = 128usize;
    let pages = 1024usize;
    let record = 32 + count * 4;
    let size = 22 + pages * 2;
    let mut bytes = vec![0; record + size];
    for (at, value) in [(4, 28), (20, 1), (28, count), (record, size)] {
        bytes[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }
    for i in 0..count {
        bytes[32 + i * 4..36 + i * 4].copy_from_slice(&((record - 28) as u32).to_le_bytes());
    }
    bytes[record + 4..record + 6].copy_from_slice(&4096u16.to_le_bytes());
    bytes[record + 6..record + 8].copy_from_slice(&6u16.to_le_bytes());
    bytes[record + 20..record + 22].copy_from_slice(&(pages as u16).to_le_bytes());
    bytes[record + 22..].fill(0xff);
    assert!(macho::dyld::decode_chained_fixups(&bytes).is_err());
}

#[test]
fn unix_thread_program_counter_reads_real_i386_eip() {
    use macho::load_command::TypedCommand;
    let image = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls").unwrap();
    let thread = image
        .typed_commands()
        .unwrap()
        .into_iter()
        .find_map(|c| match c {
            TypedCommand::UnixThread(t) => Some(t),
            _ => None,
        })
        .expect("i386 ls has LC_UNIXTHREAD");
    let pc = thread
        .program_counter(image.header.cpu_type.value, image.byte_order())
        .unwrap();
    // llvm-otool -l: i386_THREAD_STATE eip 0x00001708.
    assert_eq!(pc.value, 0x1708);
    assert_eq!(pc.size, 4);
    assert_eq!(pc.offset, thread.state_offset + 40);
    assert_eq!(
        image
            .byte_order()
            .read_u32(&image.buffer, pc.offset)
            .unwrap(),
        0x1708
    );
}

#[test]
fn unix_thread_program_counter_layouts() {
    use hexspell::field::Field;
    use macho::load_command::UnixThreadCommand;
    fn thread(flavor: u32, state: Vec<u8>) -> UnixThreadCommand {
        UnixThreadCommand {
            flavor: Field::new(flavor, 8, 4),
            count: Field::new((state.len() / 4) as u32, 12, 4),
            state_offset: 16,
            state,
        }
    }
    let (x86_64, arm64, ppc) = (0x0100_0007, 0x0100_000c, 18);
    let mut state = vec![0; 168];
    state[128..136].copy_from_slice(&0x1_0000_3f00u64.to_le_bytes());
    let pc = thread(4, state)
        .program_counter(x86_64, ByteOrder::Little)
        .unwrap();
    assert_eq!((pc.value, pc.offset, pc.size), (0x1_0000_3f00, 16 + 128, 8));

    let mut state = vec![0; 272];
    state[256..264].copy_from_slice(&0x1_0000_0480u64.to_le_bytes());
    let pc = thread(6, state.clone())
        .program_counter(arm64, ByteOrder::Little)
        .unwrap();
    assert_eq!((pc.value, pc.offset), (0x1_0000_0480, 16 + 256));
    // ARM_THREAD_STATE (unified) wraps ARM_THREAD_STATE64 in an arm_state_hdr.
    let mut unified = [6u32.to_le_bytes(), 68u32.to_le_bytes()].concat();
    unified.extend_from_slice(&state);
    let pc = thread(1, unified)
        .program_counter(arm64, ByteOrder::Little)
        .unwrap();
    assert_eq!((pc.value, pc.offset), (0x1_0000_0480, 16 + 8 + 256));

    let mut state = vec![0; 160];
    state[..4].copy_from_slice(&0x2f80u32.to_be_bytes());
    let pc = thread(1, state)
        .program_counter(ppc, ByteOrder::Big)
        .unwrap();
    assert_eq!((pc.value, pc.size), (0x2f80, 4));

    // Mismatched CPU/flavor pairs and truncated states have no PC.
    assert!(thread(4, vec![0; 168])
        .program_counter(arm64, ByteOrder::Little)
        .is_none());
    assert!(thread(6, vec![0; 64])
        .program_counter(arm64, ByteOrder::Little)
        .is_none());
}

#[test]
fn chained_pointer_formats_decode_apple_bit_layouts() {
    use macho::dyld::*;
    let decode = |format, word| decode_chained_pointer_as(format, 0, word).unwrap();
    let auth = |key, diversity, address_diversity| PointerAuth {
        key,
        diversity,
        address_diversity,
    };
    // arm64e authenticated rebase: target 32, diversity 16, addrDiv, key 2, next 11.
    let word = (1 << 63) | (3 << 51) | (2 << 49) | (1 << 48) | (0xbeef << 32) | 0x4000;
    for format in [DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_USERLAND24] {
        assert_eq!(
            decode(format, word),
            ChainedPointer::AuthRebase {
                target: 0x4000,
                auth: auth(PointerAuthKey::DA, 0xbeef, true),
                next: 24
            }
        );
    }
    // Kernel arm64e uses a four-byte stride.
    assert_eq!(
        decode(DYLD_CHAINED_PTR_ARM64E_KERNEL, (1 << 51) | 8),
        ChainedPointer::Rebase {
            target: 8,
            high8: 0,
            next: 4
        }
    );
    // Authenticated bind: 24-bit ordinals only in USERLAND24.
    let word = (3 << 62) | (1 << 49) | (7 << 32) | 0x12_3456;
    assert_eq!(
        decode(DYLD_CHAINED_PTR_ARM64E_USERLAND24, word),
        ChainedPointer::AuthBind {
            ordinal: 0x12_3456,
            auth: auth(PointerAuthKey::IB, 7, false),
            next: 0
        }
    );
    assert!(decode_chained_pointer_as(DYLD_CHAINED_PTR_ARM64E, 0, word).is_err());
    // Plain arm64e bind sign-extends its 19-bit addend.
    let word = (1 << 62) | (((-16i64 as u64) & 0x7ffff) << 32) | 5;
    assert_eq!(
        decode(DYLD_CHAINED_PTR_ARM64E_USERLAND, word),
        ChainedPointer::Bind {
            ordinal: 5,
            addend: -16,
            next: 0
        }
    );
    assert_eq!(
        decode(
            DYLD_CHAINED_PTR_ARM64E,
            (0x80 << 43) | (1 << 51) | 0x1_0000_1000
        ),
        ChainedPointer::Rebase {
            target: 0x1_0000_1000,
            high8: 0x80,
            next: 8
        }
    );
    // Kernel collections carry a cache level and optional signing.
    assert_eq!(
        decode(
            DYLD_CHAINED_PTR_64_KERNEL_CACHE,
            (1 << 63) | (2 << 51) | (1 << 30) | 0x100
        ),
        ChainedPointer::CacheRebase {
            target: 0x100,
            cache_level: 1,
            auth: Some(auth(PointerAuthKey::IA, 0, false)),
            next: 8
        }
    );
    assert_eq!(
        decode(DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE, (3 << 51) | 0x100),
        ChainedPointer::CacheRebase {
            target: 0x100,
            cache_level: 0,
            auth: None,
            next: 3
        }
    );
    // Shared cache: 34-bit offsets, keyIsData selects DA, next at bit 52.
    assert_eq!(
        decode(
            DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE,
            (1 << 63) | (1 << 52) | (1 << 51) | (9 << 34) | 0x2_0000_0000
        ),
        ChainedPointer::AuthRebase {
            target: 0x2_0000_0000,
            auth: auth(PointerAuthKey::DA, 9, false),
            next: 8
        }
    );
    assert!(decode_chained_pointer_as(DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE, 0, 1 << 42).is_err());
    assert_eq!(
        decode(
            DYLD_CHAINED_PTR_ARM64E_SEGMENTED,
            (1 << 51) | (3 << 28) | 0x40
        ),
        ChainedPointer::SegmentedRebase {
            target_segment: 3,
            target_offset: 0x40,
            auth: None,
            next: 4
        }
    );
    // 32-bit formats.
    assert_eq!(
        decode(DYLD_CHAINED_PTR_32, (1 << 31) | (2 << 26) | (63 << 20) | 9),
        ChainedPointer::Bind {
            ordinal: 9,
            addend: 63,
            next: 8
        }
    );
    assert_eq!(
        decode_chained_pointer_as(DYLD_CHAINED_PTR_32, 0x10_0000, 0x0300_0000).unwrap(),
        ChainedPointer::NonPointer {
            value: 0x0300_0000 - (0x0400_0000 + 0x10_0000) / 2,
            next: 0
        }
    );
    assert_eq!(
        decode(DYLD_CHAINED_PTR_32_CACHE, (1 << 30) | 0x1000),
        ChainedPointer::Rebase {
            target: 0x1000,
            high8: 0,
            next: 4
        }
    );
    assert_eq!(
        decode(DYLD_CHAINED_PTR_32_FIRMWARE, (5 << 26) | 0x1000),
        ChainedPointer::Rebase {
            target: 0x1000,
            high8: 0,
            next: 20
        }
    );
    assert!(matches!(
        decode_chained_pointer_as(15, 0, 0),
        Err(FileParseError::UnsupportedFeature(_))
    ));
    // Address diversity blends the slot address into the high 16 bits.
    let schema = auth(PointerAuthKey::IA, 0x1234, true);
    assert_eq!(
        schema.discriminator(0xffff_8000_0001_0008),
        0x1234_8000_0001_0008
    );
    assert_eq!(
        auth(PointerAuthKey::IA, 0x1234, false).discriminator(8),
        0x1234
    );
}

fn chained_blob(imports_format: u32, imports: &[u8], names: &[u8], segment: &[u8]) -> Vec<u8> {
    // Header (28), starts_in_image with one segment (8), segment record, imports, names.
    let starts = 28;
    let record = starts + 8;
    let imports_offset = record + segment.len();
    let symbols_offset = imports_offset + imports.len();
    let mut bytes = Vec::new();
    for value in [
        0,
        starts,
        imports_offset,
        symbols_offset,
        0,
        imports_format as usize,
        0,
        1,
        8,
    ] {
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
    }
    bytes.extend_from_slice(segment);
    bytes.extend_from_slice(imports);
    bytes.extend_from_slice(names);
    bytes
}

fn chained_segment(format: u16, max_valid: u32, page_starts: &[u16]) -> Vec<u8> {
    let page_count = page_starts.len().min(1) as u16;
    let mut bytes = ((22 + page_starts.len() * 2) as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&0x1000u16.to_le_bytes());
    bytes.extend_from_slice(&format.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&max_valid.to_le_bytes());
    bytes.extend_from_slice(&page_count.to_le_bytes());
    for start in page_starts {
        bytes.extend_from_slice(&start.to_le_bytes());
    }
    bytes
}

fn set_import_count(blob: &mut [u8], count: u32) {
    blob[16..20].copy_from_slice(&count.to_le_bytes());
}

#[test]
fn chained_imports_decode_addend_formats_and_unsigned_ordinals() {
    use macho::dyld::*;
    let segment = chained_segment(DYLD_CHAINED_PTR_64_OFFSET, 0, &[0]);
    // 8-bit ordinals above 0xF0 are special; 200 is an ordinary dylib ordinal.
    let imports = [
        (200u32 | (1 << 9)).to_le_bytes(),
        (0xffu32 | 256 | (1 << 9)).to_le_bytes(),
    ]
    .concat();
    let mut blob = chained_blob(DYLD_CHAINED_IMPORT, &imports, b"\0_a\0", &segment);
    set_import_count(&mut blob, 2);
    let fixups = decode_chained_fixups(&blob).unwrap();
    assert_eq!(fixups.imports_format, DYLD_CHAINED_IMPORT);
    assert_eq!(fixups.imports[0].library_ordinal, 200);
    assert_eq!(fixups.imports[1].library_ordinal, -1);
    assert!(fixups.imports[1].weak);
    assert_eq!(fixups.imports[0].name, "_a");

    let imports = [(2u32 | (1 << 9)).to_le_bytes(), (-8i32).to_le_bytes()].concat();
    let mut blob = chained_blob(DYLD_CHAINED_IMPORT_ADDEND, &imports, b"\0_b\0", &segment);
    set_import_count(&mut blob, 1);
    let import = &decode_chained_fixups(&blob).unwrap().imports[0];
    assert_eq!((import.library_ordinal, import.addend), (2, -8));

    // ADDEND64: 16-bit ordinal, weak bit 16, 32-bit name offset, 64-bit addend.
    let imports = [
        (300u64 | (1 << 16) | (1 << 32)).to_le_bytes(),
        0x1_0000_0000u64.to_le_bytes(),
        (0xfffeu64 | (1 << 32)).to_le_bytes(),
        0u64.to_le_bytes(),
    ]
    .concat();
    let mut blob = chained_blob(DYLD_CHAINED_IMPORT_ADDEND64, &imports, b"\0_c\0", &segment);
    set_import_count(&mut blob, 2);
    let fixups = decode_chained_fixups(&blob).unwrap();
    assert_eq!(fixups.imports[0].library_ordinal, 300);
    assert!(fixups.imports[0].weak);
    assert_eq!(fixups.imports[0].addend, 0x1_0000_0000);
    assert_eq!(fixups.imports[1].library_ordinal, -2);

    let mut compressed = blob.clone();
    compressed[24..28].copy_from_slice(&1u32.to_le_bytes());
    assert!(matches!(
        decode_chained_fixups(&compressed),
        Err(FileParseError::UnsupportedFeature(_))
    ));
}

#[test]
fn chained_segments_resolve_multi_start_pages() {
    use macho::dyld::*;
    // page_start[0] indexes the list at entry 1: starts 0x10, 0x200 (last).
    let segment = chained_segment(
        DYLD_CHAINED_PTR_32,
        0x20_0000,
        &[
            DYLD_CHAINED_PTR_START_MULTI | 1,
            0x10,
            0x200 | DYLD_CHAINED_PTR_START_LAST,
        ],
    );
    let blob = chained_blob(DYLD_CHAINED_IMPORT, &[], &[], &segment);
    let fixups = decode_chained_fixups(&blob).unwrap();
    let segment = &fixups.segments[0];
    assert_eq!(segment.pointer_format, DYLD_CHAINED_PTR_32);
    assert_eq!(segment.max_valid_pointer, 0x20_0000);
    assert_eq!(segment.page_count, 1);
    assert_eq!(segment.chain_starts(0).collect::<Vec<_>>(), [0x10, 0x200]);
    assert_eq!(segment.chain_starts(1).count(), 0);

    for starts in [
        // Unterminated list.
        &[DYLD_CHAINED_PTR_START_MULTI | 1, 0x10][..],
        // List index pointing back into the per-page entries.
        &[
            DYLD_CHAINED_PTR_START_MULTI,
            0x10 | DYLD_CHAINED_PTR_START_LAST,
        ],
        // Misaligned start.
        &[0x11],
    ] {
        let segment = chained_segment(DYLD_CHAINED_PTR_32, 0, starts);
        let blob = chained_blob(DYLD_CHAINED_IMPORT, &[], &[], &segment);
        assert!(decode_chained_fixups(&blob).is_err(), "{starts:x?}");
    }
}

/// Minimal arm64e image: __TEXT at file 0, __DATA at 0x1000 holding `slots`, fixups at 0x2000.
fn arm64e_chained_image(slots: &[u64]) -> Vec<u8> {
    use macho::dyld::{DYLD_CHAINED_IMPORT, DYLD_CHAINED_PTR_ARM64E_USERLAND24};
    fn segment(name: &[u8], vmaddr: u64, fileoff: u64, prot: u32) -> Vec<u8> {
        let mut bytes = [0x19u32.to_le_bytes(), 72u32.to_le_bytes()].concat();
        let mut segname = [0u8; 16];
        segname[..name.len()].copy_from_slice(name);
        bytes.extend_from_slice(&segname);
        for value in [vmaddr, 0x1000, fileoff, 0x1000] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for value in [prot, prot, 0, 0] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }
    let imports = (1u32 | (1 << 9)).to_le_bytes();
    let starts = chained_segment(DYLD_CHAINED_PTR_ARM64E_USERLAND24, 0, &[0]);
    let mut blob = chained_blob(DYLD_CHAINED_IMPORT, &imports, b"\0_foo\0", &starts);
    set_import_count(&mut blob, 1);
    // starts_in_image covers __TEXT (no chains) and __DATA.
    blob.splice(28..36, [2u32, 0, 12].iter().flat_map(|v| v.to_le_bytes()));
    for at in [8, 12] {
        let value = u32::from_le_bytes(blob[at..at + 4].try_into().unwrap()) + 4;
        blob[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    let mut commands = segment(b"__TEXT", 0x1_0000_0000, 0, 5);
    commands.extend(segment(b"__DATA", 0x1_0000_1000, 0x1000, 3));
    for value in [0x8000_0034u32, 16, 0x2000, blob.len() as u32] {
        commands.extend_from_slice(&value.to_le_bytes());
    }
    let mut bytes = Vec::new();
    for value in [
        0xfeed_facfu32,
        0x0100_000c,
        0x8000_0002,
        2,
        3,
        commands.len() as u32,
        0,
        0,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend(commands);
    bytes.resize(0x1000, 0);
    for slot in slots {
        bytes.extend_from_slice(&slot.to_le_bytes());
    }
    bytes.resize(0x2000, 0);
    bytes.extend(blob);
    bytes
}

#[test]
fn chained_fixup_slots_walk_arm64e_chains() {
    use macho::dyld::*;
    let slots = [
        // auth rebase -> __TEXT+0x500, IA, diversity 0x1234, address-diversified
        (1 << 63) | (1 << 51) | (1 << 48) | (0x1234 << 32) | 0x500,
        // auth bind ordinal 0, DA, diversity 0x55
        (3 << 62) | (1 << 51) | (2 << 49) | (0x55 << 32),
        // bind ordinal 0, addend -4
        (1 << 62) | (1 << 51) | ((-4i64 as u64 & 0x7ffff) << 32),
        // rebase -> image offset 0x1010, high8 0x80, end of chain
        (0x80 << 43) | 0x1010,
    ];
    let image = macho::MachO::from_buffer(arm64e_chained_image(&slots)).unwrap();
    let walked = image.chained_fixup_slots().unwrap().unwrap();
    assert_eq!(walked.len(), 4);
    for (i, slot) in walked.iter().enumerate() {
        assert_eq!(slot.segment_index, 1);
        assert_eq!(slot.pointer_format, DYLD_CHAINED_PTR_ARM64E_USERLAND24);
        assert_eq!(slot.vm_offset, 0x1000 + 8 * i as u64);
        assert_eq!((slot.raw.offset, slot.raw.size), (0x1000 + 8 * i, 8));
        assert_eq!(slot.raw.value, slots[i]);
    }
    let base = 0x1_0000_0000;
    let ChainedPointer::AuthRebase { auth, .. } = &walked[0].pointer else {
        panic!("{:?}", walked[0].pointer);
    };
    assert_eq!(auth.key, PointerAuthKey::IA);
    assert_eq!(
        auth.discriminator(base + walked[0].vm_offset),
        (0x1234 << 48) | 0x1_0000_1000
    );
    assert_eq!(walked[0].rebase_vmaddr(base), Some(0x1_0000_0500));
    assert!(matches!(
        walked[1].pointer,
        ChainedPointer::AuthBind {
            ordinal: 0,
            auth: PointerAuth {
                key: PointerAuthKey::DA,
                diversity: 0x55,
                address_diversity: false
            },
            ..
        }
    ));
    assert!(matches!(
        walked[2].pointer,
        ChainedPointer::Bind {
            ordinal: 0,
            addend: -4,
            ..
        }
    ));
    assert_eq!(walked[2].rebase_vmaddr(base), None);
    assert_eq!(walked[3].rebase_vmaddr(base), Some(0x8000_0001_0000_1010));
    assert_eq!(
        image.chained_fixups().unwrap().unwrap().imports[0].name,
        "_foo"
    );

    // Out-of-range bind ordinals and chains leaving the page are rejected.
    let bad = [(1 << 62) | 1];
    let image = macho::MachO::from_buffer(arm64e_chained_image(&bad)).unwrap();
    assert!(image.chained_fixup_slots().is_err());
    let mut bytes = arm64e_chained_image(&[0x7ff << 51]);
    bytes.truncate(0x1008);
    bytes.resize(0x2000, 0);
    bytes.extend_from_slice(&arm64e_chained_image(&[])[0x2000..]);
    let image = macho::MachO::from_buffer(bytes).unwrap();
    assert!(image.chained_fixup_slots().is_err());
    // Images without LC_DYLD_CHAINED_FIXUPS report None.
    let image = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls").unwrap();
    assert!(image.chained_fixup_slots().unwrap().is_none());
}
