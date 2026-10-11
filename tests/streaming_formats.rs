#![cfg(all(
    feature = "std",
    feature = "pe",
    feature = "elf",
    feature = "macho",
    feature = "common"
))]

use hexspell::{elf, field::ByteOrder, macho};

#[test]
fn direct_elf_entries_cover_both_classes_and_byte_orders() {
    for order in [ByteOrder::Little, ByteOrder::Big] {
        for class in [elf::header::ElfClass::Elf32, elf::header::ElfClass::Elf64] {
            let mut bytes = vec![0; 192];
            let base = 64;
            order.write_u32(&mut bytes, base, 1);
            let (program_size, section_size) = match class {
                elf::header::ElfClass::Elf32 => {
                    order.write_u32(&mut bytes, base + 4, 0x1234);
                    order.write_u32(&mut bytes, base + 8, 0x5678);
                    (32, 40)
                }
                elf::header::ElfClass::Elf64 => {
                    order.write_u64(&mut bytes, base + 8, 0x1234);
                    order.write_u64(&mut bytes, base + 16, 0x5678);
                    (56, 64)
                }
            };
            let entry =
                elf::program::ProgramHeaderEntry::parse_one(&bytes, base, class, order).unwrap();
            assert_eq!(entry.p_offset(), 0x1234);
            assert_eq!(entry.p_vaddr(), 0x5678);
            assert!(elf::program::ProgramHeaderEntry::parse_one(
                &bytes[..base + program_size - 1],
                base,
                class,
                order
            )
            .is_err());
            assert!(
                elf::program::ProgramHeaderEntry::parse_one(&bytes, usize::MAX, class, order)
                    .is_err()
            );
            let base = 128;
            order.write_u32(&mut bytes, base, 7);
            order.write_u32(&mut bytes, base + 4, 1);
            let (offset, size) = match class {
                elf::header::ElfClass::Elf32 => {
                    order.write_u32(&mut bytes, base + 16, 0x1234);
                    order.write_u32(&mut bytes, base + 20, 0x40);
                    (16, 4)
                }
                elf::header::ElfClass::Elf64 => {
                    order.write_u64(&mut bytes, base + 24, 0x1234);
                    order.write_u64(&mut bytes, base + 32, 0x40);
                    (24, 8)
                }
            };
            let mut entry =
                elf::section::SectionHeaderEntry::parse_one(&bytes, base, class, order).unwrap();
            assert_eq!(entry.sh_name(), 7);
            assert_eq!(entry.sh_offset(), 0x1234);
            assert_eq!(entry.sh_size(), 0x40);
            entry
                .sh_offset_mut()
                .update_with(&mut bytes, 0x4321, order)
                .unwrap();
            let patched = if size == 4 {
                u64::from(order.read_u32(&bytes, base + offset).unwrap())
            } else {
                order.read_u64(&bytes, base + offset).unwrap()
            };
            assert_eq!(patched, 0x4321);
            assert!(elf::section::SectionHeaderEntry::parse_one(
                &bytes[..base + section_size - 1],
                base,
                class,
                order
            )
            .is_err());
            assert!(
                elf::section::SectionHeaderEntry::parse_one(&bytes, usize::MAX, class, order)
                    .is_err()
            );
        }
    }
}

#[test]
fn macho_command_iterator_is_single_pass_and_stops_on_error() {
    let mut bytes = vec![0; 32 + 3 * 8];
    ByteOrder::Little.write_u32(&mut bytes, 0, 0xfeedfacf);
    ByteOrder::Little.write_u32(&mut bytes, 16, 3);
    ByteOrder::Little.write_u32(&mut bytes, 20, 24);
    for i in 0..3 {
        ByteOrder::Little.write_u32(&mut bytes, 32 + i * 8, (i + 1) as u32);
        ByteOrder::Little.write_u32(&mut bytes, 36 + i * 8, 8);
    }
    let view = macho::view::MachHeaders::parse(&bytes).unwrap();
    let entries: Vec<_> = view.commands().collect::<Result<_, _>>().unwrap();
    assert_eq!(entries.len(), 3);
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.cmd.offset, 32 + i * 8);
        assert_eq!(entry.cmd.value, view.command(i).unwrap().cmd.value);
    }
    ByteOrder::Little.write_u32(&mut bytes, 44, 7);
    let view = macho::view::MachHeaders::parse(&bytes).unwrap();
    let mut commands = view.commands();
    assert!(commands.next().unwrap().is_ok());
    assert!(commands.next().unwrap().is_err());
    assert!(commands.next().is_none());
    assert!(commands.next().is_none());
    // It also rejects command extents that exceed the declared command region.
    ByteOrder::Little.write_u32(&mut bytes, 44, 32);
    assert!(macho::view::MachHeaders::parse(&bytes)
        .unwrap()
        .commands()
        .nth(1)
        .unwrap()
        .is_err());
}

#[test]
fn borrowed_fat_entries_cover_both_layouts_and_byte_orders() {
    for order in [ByteOrder::Little, ByteOrder::Big] {
        for wide in [false, true] {
            let stride = if wide { 32 } else { 20 };
            let start = 8 + 2 * stride;
            let mut bytes = vec![0; start + 32];
            order.write_u32(&mut bytes, 0, if wide { 0xcafebabf } else { 0xcafebabe });
            order.write_u32(&mut bytes, 4, 2);
            for i in 0..2 {
                let base = 8 + stride * i;
                order.write_u32(&mut bytes, base, (i + 7) as u32);
                if wide {
                    order.write_u64(&mut bytes, base + 8, start as u64);
                    order.write_u64(&mut bytes, base + 16, 32);
                } else {
                    order.write_u32(&mut bytes, base + 8, start as u32);
                    order.write_u32(&mut bytes, base + 12, 32);
                }
            }
            ByteOrder::Little.write_u32(&mut bytes, start, 0xfeedfacf);
            let view = macho::fat::FatHeaders::parse(&bytes).unwrap().unwrap();
            let owned = macho::fat::FatHeader::parse(&bytes).unwrap().unwrap();
            assert_eq!(view.order, order);
            assert_eq!(view.is_64, wide);
            for (i, expected) in owned.arches.iter().enumerate() {
                let arch = view.arch(i).unwrap();
                assert_eq!(arch.cpu_type, expected.cpu_type);
                assert_eq!(arch.offset, expected.offset);
                assert_eq!(arch.size, expected.size);
                assert_eq!(view.slice(i).unwrap().as_ptr(), bytes[start..].as_ptr());
                assert_eq!(
                    macho::MachO::fat_slice_ref(&bytes, i).unwrap(),
                    view.slice(i).unwrap()
                );
            }
            assert!(view.arch(2).is_err());
            assert!(view.arch(usize::MAX).is_err());
            assert!(macho::fat::FatHeaders::parse(&bytes[..start - 1]).is_err());
            let path = std::env::temp_dir().join(format!(
                "hexspell-fat-{}-{wide}-{order:?}.bin",
                std::process::id()
            ));
            std::fs::write(&path, &bytes).unwrap();
            let selected = macho::MachO::from_fat_index_read(path.to_str().unwrap(), 1).unwrap();
            assert_eq!(selected.buffer, &bytes[start..]);
            assert!(macho::MachO::from_fat_index_read(path.to_str().unwrap(), 2).is_err());
            std::fs::remove_file(path).unwrap();
            order.write_u32(&mut bytes, 4, u32::MAX);
            assert!(macho::fat::FatHeaders::parse(&bytes).is_err());
        }
    }
}
