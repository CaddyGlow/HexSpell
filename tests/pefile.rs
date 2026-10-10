#![cfg(feature = "std")]

use std::io::Write;
use std::process::{Command, Stdio};

use hexspell::pe::{header::LOAD_CONFIG, PE};

#[path = "pefile/verification.rs"]
mod verification;

fn pefile_report(buffer: &[u8], script: &str, args: &[&str]) -> toml::Value {
    let python = std::env::var_os("HEXSPELL_PEFILE_PYTHON").unwrap_or_else(|| "python3".into());
    let mut child = Command::new(python)
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/scripts")
                .join(script),
        )
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch Python with pefile installed (see tests/scripts/README.md)");
    child.stdin.take().unwrap().write_all(buffer).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "pefile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    toml::from_str(&String::from_utf8(output.stdout).unwrap()).unwrap()
}

fn pefile_load_config(buffer: &[u8]) -> toml::Value {
    pefile_report(buffer, "pefile_load_config.py", &[])
}

#[test]
#[ignore = "requires Python and pefile==2024.8.26; run explicitly in CI"]
fn amd64_load_config_matches_pefile() {
    // Reuse the documented PE64 fixture, replacing only its in-memory directory.
    let edit_list = 0x1122_3344_5566_7788u64;
    let cookie = 0x7766_5544_3322_1100u64;
    for size in [96u32, 112, 320] {
        let mut pe = PE::from_buffer(include_bytes!("samples/sample64.exe").to_vec()).unwrap();
        let section = &pe.sections[0];
        assert!(section.size_of_raw_data.value >= size);
        let offset = section.pointer_to_raw_data.value as usize;
        let rva = section.virtual_address.value;
        let directory = &mut pe.optional_header.data_directories[LOAD_CONFIG];
        directory
            .virtual_address
            .update(&mut pe.buffer, rva)
            .unwrap();
        directory.size.update(&mut pe.buffer, size).unwrap();
        pe.buffer[offset..offset + size as usize].fill(0);
        pe.buffer[offset..offset + 4].copy_from_slice(&size.to_le_bytes());
        pe.buffer[offset + 80..offset + 88].copy_from_slice(&edit_list.to_le_bytes());
        pe.buffer[offset + 88..offset + 96].copy_from_slice(&cookie.to_le_bytes());

        let mut config = pe.load_config().unwrap().unwrap();
        assert_eq!(config.security_cookie.value, cookie);
        for expected_cookie in [cookie, 0x6655_4433_2211_00ff] {
            config
                .security_cookie
                .update(&mut pe.buffer, expected_cookie)
                .unwrap();
            let expected = pefile_load_config(&pe.buffer);
            assert_eq!(
                expected["cookie"].as_integer().unwrap() as u64,
                expected_cookie
            );
            assert_eq!(config.security_cookie.value, expected_cookie);
            assert_eq!(
                config.security_cookie.offset,
                expected["cookie_offset"].as_integer().unwrap() as usize
            );
            assert_eq!(config.security_cookie.size, 8);
            assert_eq!(
                expected["edit_list"].as_integer().unwrap() as u64,
                edit_list
            );
            assert_eq!(
                expected["edit_list_offset"].as_integer().unwrap() as usize,
                offset + 80
            );
        }
    }
}
