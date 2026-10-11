//! Generate a Windows DLL: pe_dll x86|x64 OUTPUT.
#[allow(dead_code)] // Shared generation routines are exercised together by integration tests.
mod support;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: pe_dll x86|x64 OUTPUT".into());
    }
    std::fs::write(&args[2], support::dll(support::target(&args[1])?)?.buffer)?;
    Ok(())
}
