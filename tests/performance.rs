#![cfg(all(
    feature = "std",
    feature = "pe",
    feature = "elf",
    feature = "macho",
    feature = "common"
))]

#[path = "support/alloc.rs"]
mod allocations;

use allocations::{measured, CountingAllocator};
use hexspell::{elf, macho, pe, strings};
use std::borrow::Cow;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn read_only_traversals_do_not_allocate() {
    for path in ["tests/samples/sample1.exe", "tests/samples/sample64.exe"] {
        let bytes = std::fs::read(path).unwrap();
        let pe = pe::PE::from_slice(&bytes).unwrap();
        let (total, count, _) = measured(|| {
            let mut total = 0;
            for dll in pe.imports_iter().unwrap() {
                let dll = dll.unwrap();
                assert!(matches!(dll.dll_name, Cow::Borrowed(_)));
                for entry in dll.entries {
                    match entry.unwrap() {
                        pe::read::ImportEntryRef::ByName { name, .. } => {
                            assert!(matches!(name, Cow::Borrowed(_)));
                            total += name.len();
                        }
                        pe::read::ImportEntryRef::Ordinal { .. } => total += 1,
                    }
                }
            }
            for block in pe.base_relocations_iter().unwrap() {
                total += block.unwrap().entries().count();
            }
            total += pe.debug_iter().unwrap().count();
            total
        });
        assert!(total > 0);
        assert_eq!(count, 0, "{path}");
        let (_, count, _) = measured(|| pe::PE::from_slice(&bytes).unwrap());
        assert_eq!(count, 1, "only the section vector should allocate");
    }
    let bytes = std::fs::read("tests/samples/sample2.dll").unwrap();
    let pe = pe::PE::from_slice(&bytes).unwrap();
    let records = [0u8; 56];
    let (_, count, _) = measured(|| {
        for entry in pe::read::DebugEntries::new(&records, 0, records.len()).unwrap() {
            std::hint::black_box(entry.unwrap());
        }
    });
    assert_eq!(count, 0);
    let (_, count, _) = measured(|| {
        for entry in pe.exports_iter().unwrap() {
            std::hint::black_box(entry.unwrap());
        }
        for entry in pe.export_functions_iter().unwrap() {
            std::hint::black_box(entry.unwrap());
        }
    });
    assert_eq!(count, 0);

    let bytes = std::fs::read("tests/samples/linux").unwrap();
    let view = elf::view::ElfHeaders::parse(&bytes).unwrap();
    let (_, count, _) = measured(|| {
        for i in 0..view.program_count().unwrap() {
            std::hint::black_box(view.program(i).unwrap());
        }
        for i in 0..view.section_count().unwrap() {
            std::hint::black_box(view.section(i).unwrap());
        }
    });
    assert_eq!(count, 0);
    let elf = elf::ELF::from_slice(&bytes).unwrap();
    let (_, count, _) = measured(|| {
        for i in 0..elf.section_headers.len() {
            std::hint::black_box(elf.section_name_ref(i).unwrap());
        }
    });
    assert_eq!(count, 0);
    let table = elf.symbols().unwrap().unwrap();
    let (_, count, _) = measured(|| {
        for symbol in &table.symbols {
            let name = table.name_ref(&bytes, symbol).unwrap();
            assert!(matches!(name, Cow::Borrowed(_)));
            if !name.is_empty() {
                assert_eq!(
                    name.as_ptr(),
                    bytes[table.strtab_offset + symbol.st_name() as usize..].as_ptr()
                );
            }
        }
        assert!(elf.section_index_by_name(".text").is_some());
    });
    assert_eq!(count, 0);
    let (_, count, _) = measured(|| elf::ELF::from_slice(&bytes).unwrap());
    assert_eq!(count, 2, "one allocation per validated table");

    let bytes = std::fs::read("tests/samples/machO-OSX-x86-ls").unwrap();
    let view = macho::view::MachHeaders::parse(&bytes).unwrap();
    let (_, count, _) = measured(|| {
        for command in view.commands() {
            std::hint::black_box(command.unwrap());
        }
    });
    assert_eq!(count, 0);
    let image = macho::MachO::from_slice(&bytes).unwrap();
    let (_, count, _) = measured(|| {
        for path in image.linked_dylibs_iter() {
            assert!(matches!(path.unwrap(), Cow::Borrowed(_)));
        }
    });
    assert_eq!(count, 0);
    let (_, count, _) = measured(|| macho::MachO::from_slice(&bytes).unwrap());
    assert_eq!(count, 3, "one allocation per validated table");
}

#[test]
fn borrowed_strings_preserve_lossy_and_pool_policies() {
    let bytes = b"hello\0";
    let (name, count, _) = measured(|| strings::read_c_string_ref(bytes, 0).unwrap());
    assert_eq!(count, 0);
    assert!(matches!(name, Cow::Borrowed(_)));
    assert_eq!(name.as_ptr(), bytes.as_ptr());
    let (name, count, _) = measured(|| strings::read_c_string_ref(b"\xff\0", 0).unwrap());
    assert!(count > 0);
    assert_eq!(name, "\u{fffd}");
    assert!(strings::read_c_string_ref(b"unterminated", 0).is_err());
    assert!(strings::read_c_string_in_pool_ref(bytes, usize::MAX, 10, 1).is_err());
    let pool = strings::CStringPool { offset: 0, size: 6 };
    assert_eq!(pool.resolve_ref(b"\0hello", 1).unwrap(), "hello");
}

#[test]
fn fat_selection_and_hostile_counts_do_not_allocate() {
    let mut bytes = [0u8; 60];
    let order = hexspell::field::ByteOrder::Big;
    order.write_u32(&mut bytes, 0, 0xcafebabe);
    order.write_u32(&mut bytes, 4, 1);
    order.write_u32(&mut bytes, 16, 28);
    order.write_u32(&mut bytes, 20, 32);
    hexspell::field::ByteOrder::Little.write_u32(&mut bytes, 28, 0xfeedfacf);
    let (_, count, _) = measured(|| {
        let fat = macho::fat::FatHeaders::parse(&bytes).unwrap().unwrap();
        std::hint::black_box(fat.arch(0).unwrap());
        std::hint::black_box(macho::MachO::fat_slice_ref(&bytes, 0).unwrap());
        std::hint::black_box(macho::MachO::from_slice(&bytes).unwrap());
    });
    assert_eq!(count, 0);

    let mut pe = pe::PE::from_file("tests/samples/sample1.exe").unwrap();
    pe.coff_header
        .number_of_sections
        .update(&mut pe.buffer, u16::MAX)
        .unwrap();
    let (result, count, _) = measured(|| pe::PE::from_slice(&pe.buffer));
    assert!(result.is_err());
    assert_eq!(count, 0);

    let mut bytes = std::fs::read("tests/samples/linux").unwrap();
    let header = elf::view::ElfHeaders::parse(&bytes).unwrap();
    let order = header.byte_order().unwrap();
    let mut ph_num = header.header.ph_num;
    ph_num.update_with(&mut bytes, u16::MAX, order).unwrap();
    let (result, count, _) = measured(|| elf::ELF::from_slice(&bytes));
    assert!(result.is_err());
    assert_eq!(count, 0);

    let mut bytes = [0u8; 32];
    hexspell::field::ByteOrder::Little.write_u32(&mut bytes, 0, 0xfeedfacf);
    hexspell::field::ByteOrder::Little.write_u32(&mut bytes, 16, u32::MAX);
    let (result, count, _) = measured(|| macho::MachO::from_slice(&bytes));
    assert!(result.is_err());
    assert_eq!(count, 0);

    let mut pe = pe::PE::from_file("tests/samples/sample2.dll").unwrap();
    let mut names = pe.exports().unwrap().unwrap().directory.number_of_names;
    names.update(&mut pe.buffer, u32::MAX).unwrap();
    let (result, count, _) = measured(|| pe.exports());
    assert!(result.is_err());
    assert_eq!(count, 0);
}

#[test]
fn chained_fixup_alias_expansion_has_bounded_allocations() {
    let imports = 1024usize;
    let names = 32 + imports * 4;
    let mut bytes = vec![0; names + 8193];
    for (at, value) in [(4, 28), (8, 32), (12, names), (16, imports), (20, 1)] {
        bytes[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }
    bytes[names..names + 8192].fill(b'x');
    let (result, _, allocated) = measured(|| macho::dyld::decode_chained_fixups(&bytes));
    assert!(result.is_err());
    assert!(
        allocated < bytes.len() * 16,
        "allocated {allocated} bytes for {} input bytes",
        bytes.len()
    );
}
