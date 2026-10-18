#![cfg(all(feature = "std", feature = "macho"))]

use std::process::Command;

use hexspell::macho::dyld::{ChainedPointer, PointerAuthKey};
use hexspell::macho::MachO;

const VM_PROT_EXECUTE: u32 = 4;

fn lief_report(path: &str, slice: usize) -> toml::Value {
    let python = std::env::var_os("HEXSPELL_LIEF_PYTHON").unwrap_or_else(|| "python3".into());
    let output = Command::new(python)
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/scripts/lief_chained_fixups.py"),
        )
        .arg(path)
        .arg(slice.to_string())
        .output()
        .expect("launch Python with LIEF installed (see tests/scripts/README.md)");
    assert!(
        output.status.success(),
        "LIEF failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    toml::from_str(&String::from_utf8(output.stdout).unwrap()).unwrap()
}

fn strings(report: &toml::Value, key: &str) -> Vec<String> {
    report[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// Compares one slice with LIEF and returns (binds, rebases, authenticated slots).
fn compare_slice(path: &str, slice: usize, image: &MachO) -> (usize, usize, usize) {
    let report = lief_report(path, slice);
    let fixups = image.chained_fixups().unwrap().expect("chained fixups");
    let slots = image.chained_fixup_slots().unwrap().unwrap();
    assert_eq!(
        fixups.imports.len() as i64,
        report["imports_count"].as_integer().unwrap()
    );
    let base = image
        .segments
        .iter()
        .find(|s| s.fileoff() == 0 && s.filesize() > 0)
        .unwrap()
        .vmaddr();
    let segment_of = |address: u64| {
        image
            .segments
            .iter()
            .find(|s| (s.vmaddr()..s.vmaddr() + s.vmsize()).contains(&address))
    };
    let (mut binds, mut rebases, mut authenticated) = (Vec::new(), Vec::new(), 0);
    for slot in &slots {
        let address = base + slot.vm_offset;
        // Every slot is file-backed: the raw Field must locate the same word.
        let segment = &image.segments[slot.segment_index];
        assert_eq!(
            slot.raw.offset as u64,
            segment.fileoff() + address - segment.vmaddr()
        );
        match &slot.pointer {
            ChainedPointer::Bind {
                ordinal, addend, ..
            } => {
                let import = &fixups.imports[*ordinal as usize];
                binds.push(format!(
                    "{address:#x} {} {}",
                    import.name,
                    import.addend + addend
                ));
            }
            ChainedPointer::AuthBind { ordinal, .. } => {
                authenticated += 1;
                let import = &fixups.imports[*ordinal as usize];
                binds.push(format!("{address:#x} {} {}", import.name, import.addend));
            }
            ChainedPointer::Rebase { .. } | ChainedPointer::AuthRebase { .. } => {
                let target = slot.rebase_vmaddr(base).unwrap();
                rebases.push(format!("{address:#x} {target:#x}"));
                if let ChainedPointer::AuthRebase { auth, .. } = &slot.pointer {
                    authenticated += 1;
                    // Signing schema sanity: instruction keys sign code
                    // pointers, data keys sign pointers to non-code.
                    let executable =
                        segment_of(target).is_some_and(|s| s.initprot() & VM_PROT_EXECUTE != 0);
                    let instruction = matches!(auth.key, PointerAuthKey::IA | PointerAuthKey::IB);
                    assert_eq!(
                        executable, instruction,
                        "{path}[{slice}] {address:#x} -> {target:#x} signed with {:?}",
                        auth.key
                    );
                }
            }
            other => panic!("{path}[{slice}] unexpected {other:?} in a userland image"),
        }
    }
    binds.sort();
    rebases.sort();
    assert_eq!(binds, strings(&report, "binds"), "{path}[{slice}] binds");
    assert_eq!(
        rebases,
        strings(&report, "rebases"),
        "{path}[{slice}] rebases"
    );
    (binds.len(), rebases.len(), authenticated)
}

#[test]
#[ignore = "requires Python with LIEF and HEXSPELL_MACHO_FIXUP_FILES; see tests/scripts/README.md"]
fn chained_fixups_match_lief() {
    let files = std::env::var("HEXSPELL_MACHO_FIXUP_FILES")
        .expect("set HEXSPELL_MACHO_FIXUP_FILES to colon-separated Mach-O paths");
    for path in files.split(':').filter(|p| !p.is_empty()) {
        let arches = MachO::fat_architectures(path).unwrap();
        let count = arches.len().max(1);
        for slice in 0..count {
            let image = if arches.is_empty() {
                MachO::from_file(path).unwrap()
            } else {
                MachO::from_fat_index(path, slice).unwrap()
            };
            let (binds, rebases, authenticated) = compare_slice(path, slice, &image);
            eprintln!(
                "{path}[{slice}] cpu {:#x}: {binds} binds, {rebases} rebases, {authenticated} authenticated",
                image.header.cpu_type.value
            );
        }
    }
}
