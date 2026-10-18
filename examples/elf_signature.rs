//! Edit or extract Linux module-style appended signature containers; no cryptography.
use hexspell::elf::ELF;

fn roundtrip(image: &mut ELF) -> Result<(), Box<dyn std::error::Error>> {
    let signature = image
        .appended_signature()?
        .ok_or("expected appended signature")?;
    let blob = signature.data(&image.buffer)?.to_vec();
    let original = image.buffer.clone();
    image.set_appended_signature(&blob)?;
    if image.buffer != original {
        return Err("signature round-trip changed bytes".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("attach") if args.len() == 4 => {
            let mut image = ELF::from_file(&args[1])?;
            image.set_appended_signature(&std::fs::read(&args[2])?)?;
            image.write_file(&args[3])?;
        }
        Some("remove") if args.len() == 3 => {
            let mut image = ELF::from_file(&args[1])?;
            image.remove_appended_signature()?;
            image.write_file(&args[2])?;
        }
        Some("roundtrip") if args.len() == 3 => {
            let mut image = ELF::from_file(&args[1])?;
            roundtrip(&mut image)?;
            image.write_file(&args[2])?;
        }
        Some("extract") if args.len() == 4 => {
            let image = ELF::from_file(&args[1])?;
            let signature = image.appended_signature()?.ok_or("expected appended signature")?;
            std::fs::write(&args[2], signature.signed_data(&image.buffer)?)?;
            std::fs::write(&args[3], signature.data(&image.buffer)?)?;
        }
        _ => return Err("usage: elf_signature attach ELF PKCS7 OUTPUT | remove ELF OUTPUT | roundtrip ELF OUTPUT | extract ELF PAYLOAD PKCS7".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexspell::elf::build::{Binding, ElfBuilder, SectionSpec, SegmentSpec, Target};
    use hexspell::elf::signature::MODULE_SIGNATURE_MARKER;

    #[test]
    fn roundtrip_preserves_single_and_stacked_signatures() {
        let mut builder = ElfBuilder::new(Target::LinuxX86_64);
        let text = builder.add_segment(SegmentSpec::RX).unwrap();
        let code = builder
            .add_section(Some(&text), SectionSpec::new(".text", vec![0xc3]))
            .unwrap();
        let entry = builder
            .define_symbol("_start", &code, 0, 1, Binding::Global)
            .unwrap();
        builder.set_entry(&entry).unwrap();
        let mut image = builder.build().unwrap();
        for signature in [b"inner", b"outer"] {
            image.buffer.extend_from_slice(signature);
            image.buffer.extend_from_slice(&[0, 0, 2, 0, 0, 0, 0, 0]);
            image
                .buffer
                .extend_from_slice(&(signature.len() as u32).to_be_bytes());
            image.buffer.extend_from_slice(MODULE_SIGNATURE_MARKER);
            let original = image.buffer.clone();

            roundtrip(&mut image).unwrap();

            assert_eq!(image.buffer, original);
        }
    }
}
