use std::{env, error::Error, fs, path::PathBuf};
fn main() -> Result<(), Box<dyn Error>> {
    let output = PathBuf::from(
        env::args_os()
            .nth(1)
            .ok_or("usage: seed-executables OUTPUT")?,
    );
    let samples = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/samples");
    for target in ["parse", "roundtrip", "signatures"] {
        let directory = output.join(target);
        fs::create_dir_all(&directory)?;
        for (name, bytes) in hexspell_fuzz::synthetic_seeds() {
            fs::write(directory.join(name), bytes)?;
        }
        for (name, bytes) in hexspell_fuzz::signature_seeds() {
            fs::write(directory.join(name), bytes)?;
        }
        for name in [
            "sample1.exe",
            "sample64.exe",
            "sample2.dll",
            "linux",
            "machO-OSX-x86-ls",
        ] {
            let bytes = fs::read(samples.join(name))?;
            fs::write(directory.join(name), &bytes)?;
            for length in [0, 1, 16, 32, 64, 128, 256] {
                fs::write(
                    directory.join(format!("{name}-prefix-{length}")),
                    &bytes[..length.min(bytes.len())],
                )?;
            }
        }
    }
    Ok(())
}
