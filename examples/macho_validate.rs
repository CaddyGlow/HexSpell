//! Reparse signed images and package/extract generated FAT slices for acceptance.
use hexspell::macho::{
    fat::{FatArch, FatHeader},
    load_command::LC_CODE_SIGNATURE,
    MachO,
};
fn validate(bytes: Vec<u8>) -> Result<MachO, Box<dyn std::error::Error>> {
    let image = MachO::from_buffer(bytes)?;
    let order = image.byte_order();
    for command in &image.load_commands {
        if command.cmd.value == LC_CODE_SIGNATURE {
            if command.cmdsize.value != 16 {
                return Err("unsupported signature command size".into());
            }
            let base = command.cmd.offset;
            let start = order.read_u32(&image.buffer, base + 8)? as usize;
            let size = order.read_u32(&image.buffer, base + 12)? as usize;
            let end = start.checked_add(size).ok_or("signature extent overflow")?;
            if start & 15 != 0 || end > image.buffer.len() || size < 12 {
                return Err("invalid signature extent".into());
            }
            // Apple embedded-signature SuperBlob header is big endian.
            let header = &image.buffer[start..end];
            let magic = u32::from_be_bytes(header[..4].try_into()?);
            let length = u32::from_be_bytes(header[4..8].try_into()?) as usize;
            if magic != 0xfade0cc0 || length > size || length < 12 {
                return Err("invalid signature SuperBlob".into());
            }
        }
    }
    Ok(image)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("validate") if args.len() == 2 => {
            let image = validate(std::fs::read(&args[1])?)?;
            let _ = image.symbols()?;
            let _ = image.exports()?;
            let _ = image.chained_fixups()?;
            println!("reparsed {} commands and {} sections", image.load_commands.len(), image.sections.len());
        }
        Some("pack") if args.len() >= 4 => {
            let mut images = Vec::new();
            for path in &args[2..] { images.push(validate(std::fs::read(path)?)?); }
            let slices: Vec<_> = images.iter().map(|image| (FatArch {
                cpu_type: image.header.cpu_type.value,
                cpu_subtype: image.header.cpu_subtype.value,
                offset: 0, size: 0, align: 14,
            }, image.buffer.as_slice())).collect();
            std::fs::write(&args[1], FatHeader::build(&slices)?)?;
        }
        Some("extract") if args.len() == 4 => {
            let bytes = std::fs::read(&args[1])?;
            let header = FatHeader::parse(&bytes)?.ok_or("expected FAT image")?;
            let index: usize = args[2].parse()?;
            let arch = header.arches.get(index).ok_or("slice index out of range")?;
            let slice = header.slice_ref(&bytes, arch)?;
            validate(slice.to_vec())?;
            std::fs::write(&args[3], slice)?;
        }
        _ => return Err("usage: macho_validate validate FILE | pack OUTPUT THIN THIN... | extract FAT INDEX OUTPUT".into()),
    }
    Ok(())
}
