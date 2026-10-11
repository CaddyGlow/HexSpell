//! Edit or extract Linux module-style appended signature containers; no cryptography.
use hexspell::elf::ELF;
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
            let signature = image.appended_signature()?.ok_or("expected appended signature")?;
            let blob = signature.data(&image.buffer)?.to_vec();
            let original = image.buffer.clone();
            image.remove_appended_signature()?;
            image.set_appended_signature(&blob)?;
            if image.buffer != original { return Err("signature round-trip changed bytes".into()); }
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
