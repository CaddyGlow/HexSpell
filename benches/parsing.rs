//! Run with cargo bench --bench parsing. File I/O and fixture setup are untimed.
#[path = "../tests/support/alloc.rs"]
mod allocations;

use allocations::{measured, CountingAllocator};
use hexspell::{elf, field::ByteOrder, macho, pe};
use std::hint::black_box;
use std::time::{Duration, Instant};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn run(name: &str, mut action: impl FnMut() -> usize) {
    let expected = black_box(action());
    let (result, calls, bytes) = measured(&mut action);
    assert_eq!(result, expected);
    let mut samples = Vec::new();
    for _ in 0..7 {
        let start = Instant::now();
        let mut iterations = 0;
        loop {
            for _ in 0..64 {
                black_box(action());
            }
            iterations += 64;
            if start.elapsed() >= Duration::from_millis(20) {
                break;
            }
        }
        samples.push(start.elapsed().as_nanos() / iterations);
    }
    samples.sort_unstable();
    println!("{name},{},{calls},{bytes}", samples[samples.len() / 2]);
}

fn main() {
    println!("workload,median_ns,allocation_calls,requested_bytes");
    let bytes = std::fs::read("tests/samples/sample64.exe").unwrap();
    run("pe/full_borrowed", || {
        pe::PE::from_slice(black_box(&bytes))
            .unwrap()
            .sections
            .len()
    });
    run("pe/full_plus_relocations", || {
        let image = pe::PE::from_slice(black_box(&bytes)).unwrap();
        black_box(image.base_relocations().unwrap());
        image.sections.len()
    });
    let image = pe::PE::from_slice(&bytes).unwrap();
    run("pe/relocations_collected", || {
        image
            .base_relocations()
            .unwrap()
            .iter()
            .map(|b| {
                b.entries
                    .iter()
                    .map(|entry| usize::from(entry.raw.value))
                    .sum::<usize>()
            })
            .sum()
    });
    run("pe/relocations_streamed", || {
        image
            .base_relocations_iter()
            .unwrap()
            .map(|b| {
                b.unwrap()
                    .entries()
                    .map(|entry| usize::from(entry.raw.value))
                    .sum::<usize>()
            })
            .sum()
    });
    run("pe/imports_collected", || {
        image
            .imports()
            .unwrap()
            .dlls
            .iter()
            .map(|d| {
                d.dll_name.len()
                    + d.entries
                        .iter()
                        .map(|e| match e {
                            pe::import::ImportEntry::ByName { by_name, .. } => by_name.name.len(),
                            pe::import::ImportEntry::Ordinal { .. } => 1,
                        })
                        .sum::<usize>()
            })
            .sum()
    });
    run("pe/imports_streamed", || {
        image
            .imports_iter()
            .unwrap()
            .map(|dll| {
                let dll = dll.unwrap();
                dll.dll_name.len()
                    + dll
                        .entries
                        .map(|e| match e.unwrap() {
                            pe::read::ImportEntryRef::ByName { name, .. } => name.len(),
                            pe::read::ImportEntryRef::Ordinal { .. } => 1,
                        })
                        .sum::<usize>()
            })
            .sum()
    });
    let index = image.rva_index();
    run("pe/imports_streamed_indexed", || {
        image
            .imports_iter()
            .unwrap()
            .with_index(&index)
            .unwrap()
            .map(|dll| {
                let dll = dll.unwrap();
                dll.dll_name.len()
                    + dll
                        .entries
                        .map(|e| match e.unwrap() {
                            pe::read::ImportEntryRef::ByName { name, .. } => name.len(),
                            pe::read::ImportEntryRef::Ordinal { .. } => 1,
                        })
                        .sum::<usize>()
            })
            .sum()
    });

    let bytes = std::fs::read("tests/samples/sample2.dll").unwrap();
    let image = pe::PE::from_slice(&bytes).unwrap();
    run("pe/exports_collected", || {
        image
            .exports()
            .unwrap()
            .unwrap()
            .named
            .iter()
            .map(|e| e.name.len())
            .sum()
    });
    run("pe/exports_streamed", || {
        image
            .exports_iter()
            .unwrap()
            .map(|e| e.unwrap().name.len())
            .sum()
    });

    let bytes = std::fs::read("tests/samples/linux").unwrap();
    let view = elf::view::ElfHeaders::parse(&bytes).unwrap();
    run("elf/full_borrowed", || {
        elf::ELF::from_slice(black_box(&bytes))
            .unwrap()
            .section_headers
            .len()
    });
    run("elf/sections_direct", || {
        (0..view.section_count().unwrap())
            .map(|i| view.section(i).unwrap().sh_name() as usize)
            .sum()
    });
    let image = elf::ELF::from_slice(&bytes).unwrap();
    run("elf/names_owned", || {
        (0..image.section_headers.len())
            .map(|i| image.section_name(i).unwrap().len())
            .sum()
    });
    run("elf/names_borrowed", || {
        (0..image.section_headers.len())
            .map(|i| image.section_name_ref(i).unwrap().len())
            .sum()
    });

    let bytes = std::fs::read("tests/samples/machO-OSX-x86-ls").unwrap();
    let view = macho::view::MachHeaders::parse(&bytes).unwrap();
    run("macho/commands_indexed_rescan", || {
        (0..view.header.ncmds.value as usize)
            .map(|i| view.command(i).unwrap().cmdsize.value as usize)
            .sum()
    });
    run("macho/commands_streamed", || {
        view.commands()
            .map(|c| c.unwrap().cmdsize.value as usize)
            .sum()
    });
    let image = macho::MachO::from_slice(&bytes).unwrap();
    run("macho/dylibs_owned", || {
        image.linked_dylibs().unwrap().iter().map(String::len).sum()
    });
    run("macho/dylibs_borrowed", || {
        image.linked_dylibs_iter().map(|n| n.unwrap().len()).sum()
    });

    let metadata = macho::fat::FatArch {
        cpu_type: 7,
        cpu_subtype: 0,
        offset: 0,
        size: 0,
        align: 0,
    };
    let fat =
        macho::fat::FatHeader::build(&[(metadata.clone(), &bytes), (metadata, &bytes)]).unwrap();
    run("macho/fat_arches_collected", || {
        macho::fat::FatHeader::parse(&fat).unwrap().unwrap().arches[0].offset as usize
    });
    run("macho/fat_arch_selected", || {
        macho::fat::FatHeaders::parse(&fat)
            .unwrap()
            .unwrap()
            .arch(0)
            .unwrap()
            .offset as usize
    });

    for count in [4, 16, 128] {
        let bytes = vec![0; 512 + count * 512];
        let mut sections = Vec::new();
        for i in 0..count {
            let mut raw = [0; 40];
            ByteOrder::Little.write_u32(&mut raw, 12, (0x1000 * (i + 1)) as u32);
            ByteOrder::Little.write_u32(&mut raw, 16, 512);
            ByteOrder::Little.write_u32(&mut raw, 20, (512 * (i + 1)) as u32);
            sections.push(pe::section::PeSection::parse_section(&raw, 0).unwrap());
        }
        let queries: Vec<_> = sections
            .iter()
            .map(|s| s.virtual_address.value + 123)
            .collect();
        run(&format!("pe/rva_index_build/{count}"), || {
            black_box(pe::read::RvaIndex::new(&bytes, &sections));
            count
        });
        let index = pe::read::RvaIndex::new(&bytes, &sections);
        run(&format!("pe/rva_linear/{count}"), || {
            queries
                .iter()
                .map(|&rva| pe::import::rva_to_offset(&bytes, &sections, black_box(rva)).unwrap())
                .sum()
        });
        run(&format!("pe/rva_indexed/{count}"), || {
            queries
                .iter()
                .map(|&rva| index.rva_to_offset(black_box(rva)).unwrap())
                .sum()
        });
    }
}
