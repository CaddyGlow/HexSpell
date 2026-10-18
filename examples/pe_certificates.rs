//! Round-trip or remove opaque PE certificate tables without cryptographic operations.
use hexspell::pe::PE;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: pe_certificates [roundtrip|remove] INPUT OUTPUT".into());
    }
    let mut image = PE::from_file(&args[1])?;
    match args[0].as_str() {
        "roundtrip" => {
            let table = image.owned_certificates()?;
            image.remove_certificates()?;
            for certificate in &table.certificates {
                image.append_certificate(certificate)?;
            }
            image.replace_certificates(&table)?;
        }
        "remove" => {
            image.remove_certificates()?;
        }
        _ => return Err("expected roundtrip or remove".into()),
    }
    image.write_file(&args[2])?;
    Ok(())
}
