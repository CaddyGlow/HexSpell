//! Edit generated example resources transactionally, preserving unknown resources.
//! Usage: pe_resources INPUT OUTPUT preserve|strip
use hexspell::{
    errors::FileParseError,
    pe::{
        resource::{version::VersionBlock, ResourceKey, ResourceNode, SignaturePolicy},
        PE,
    },
};

fn edit(image: &mut PE, policy: SignaturePolicy) -> Result<(), FileParseError> {
    let mut resources = image.owned_resources()?;
    resources.set_string(
        1,
        1033,
        "Edited resource".encode_utf16().collect::<Vec<_>>(),
    )?;
    let version_path = [
        ResourceKey::Id(16),
        ResourceKey::Id(1),
        ResourceKey::Id(1033),
    ];
    if let Some(ResourceNode::Data(data)) = resources.get(&version_path) {
        let mut data = data.clone();
        let mut version = VersionBlock::parse(&data.bytes)?;
        // VS_FIXEDFILEINFO dwFileVersionMS: major 2, minor 0.
        if version.value.len() < 52 {
            return Err(FileParseError::InvalidFileFormat);
        }
        version.value[8..12].copy_from_slice(&0x0002_0000u32.to_le_bytes());
        data.bytes = version.serialize()?;
        resources.replace(&version_path, ResourceNode::Data(data))?;
    }
    let icon_key = ResourceKey::Id(1);
    if resources
        .get(&[ResourceKey::Id(14), icon_key.clone()])
        .is_some()
    {
        let icon = resources.icon(&icon_key, 1033)?;
        // A coordinated replacement assigns fresh, unused image IDs.
        resources.set_icon(icon_key, 1033, &icon)?;
    }
    let report = image.replace_resources(&resources, policy)?;
    eprintln!(
        "resource RVA={:#x}, bytes={}, signature={:?}",
        report.section_rva, report.size, report.signature
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 {
        return Err("usage: pe_resources INPUT OUTPUT preserve|strip".into());
    }
    let policy = if args[3] == "preserve" {
        SignaturePolicy::PreserveBytes
    } else if args[3] == "strip" {
        SignaturePolicy::Strip
    } else {
        return Err("signature policy must be preserve or strip".into());
    };
    let mut image = PE::from_buffer(std::fs::read(&args[1])?)?;
    edit(&mut image, policy)?;
    std::fs::write(&args[2], &image.buffer)?;
    Ok(())
}
