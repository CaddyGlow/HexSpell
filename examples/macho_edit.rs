//! Append custom data transactionally while preserving executable addresses.
use hexspell::macho::{
    edit::{rebuild_fat_slice, MachOEdit, SignaturePolicy},
    fat::FatHeader,
    MachO,
};
fn apply(edit: &mut MachOEdit<'_>, custom: Option<usize>) -> hexspell::errors::Result<()> {
    let payload = vec![b'X'; if custom.is_some() { 128 } else { 32768 }];
    if let Some(index) = custom {
        edit.grow_custom_section(index, &payload)?;
    } else {
        edit.add_custom_section("__metadata", &payload)?;
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if !(3..=5).contains(&args.len()) {
        return Err("usage: macho_edit INPUT OUTPUT [strip] [fat=INDEX]".into());
    }
    let mut policy = SignaturePolicy::Reject;
    let mut slice = None;
    for option in &args[3..] {
        if option == "strip" {
            policy = SignaturePolicy::Strip;
        } else if let Some(index) = option.strip_prefix("fat=") {
            slice = Some(index.parse::<usize>()?);
        } else {
            return Err("usage: macho_edit INPUT OUTPUT [strip] [fat=INDEX]".into());
        }
    }
    let mut buffer = std::fs::read(&args[1])?;
    let selected = if let Some(index) = slice {
        let fat = FatHeader::parse(&buffer)?.ok_or("fat= requires a FAT container")?;
        let arch = fat
            .arches
            .get(index)
            .ok_or("FAT slice index out of range")?;
        MachO::from_buffer(fat.slice_ref(&buffer, arch)?.to_vec())?
    } else {
        MachO::from_buffer(buffer.clone())?
    };
    let custom = selected
        .sections
        .iter()
        .position(|s| s.segment_name() == "__CUSTOM");
    let report = if let Some(index) = slice {
        rebuild_fat_slice(&mut buffer, index, policy, |edit| apply(edit, custom))?
    } else {
        let mut image = selected;
        let mut edit = MachOEdit::with_signature_policy(&mut image, policy)?;
        apply(&mut edit, custom)?;
        let report = edit.commit()?;
        buffer = image.buffer;
        report
    };
    std::fs::write(&args[2], &buffer)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&args[2], std::fs::Permissions::from_mode(0o755))?;
    }
    println!(
        "updated {} ranges; existing addresses preserved; external signing {}",
        report.changed_ranges.len(),
        if report.requires_signing {
            "required"
        } else {
            "available"
        }
    );
    Ok(())
}
