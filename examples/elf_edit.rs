//! Replace isolated nonallocated custom data without moving executable addresses.
use hexspell::elf::{
    edit::{BuildIdPolicy, ElfEdit},
    ELF,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: elf_edit INPUT OUTPUT".into());
    }
    let mut image = ELF::from_file(&args[1])?;
    let index = (0..image.section_headers.len())
        .find(|&i| image.section_name(i).ok().as_deref() == Some(".custom"));
    let mut edit = ElfEdit::new(&mut image, BuildIdPolicy::Reject)?;
    if let Some(index) = index {
        edit.grow_custom_section(index, &vec![b'X'; 32768])?;
    } else {
        edit.add_custom_section(".custom", &vec![b'X'; 32768])?;
    }
    let report = edit.commit()?;
    std::fs::write(&args[2], &image.buffer)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&args[2], std::fs::Permissions::from_mode(0o755))?;
    }
    println!(
        "updated {} range(s); addresses preserved",
        report.changed_ranges.len()
    );
    Ok(())
}
