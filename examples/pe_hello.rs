//! Generate an x86 or x64 Windows GUI executable: pe_hello x86|x64 OUTPUT.
#[allow(dead_code)] // Shared generation routines are exercised together by integration tests.
mod support;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if !(args.len() == 3
        || args.len() == 4
            && matches!(args[3].as_str(), "--no-tls-callback" | "--conflicting-base"))
    {
        return Err(
            "usage: pe_hello x86|x64 OUTPUT [--no-tls-callback | --conflicting-base]".into(),
        );
    }
    std::fs::write(
        &args[2],
        support::hello_with_options(
            support::target(&args[1])?,
            args.get(3).is_none_or(|arg| arg != "--no-tls-callback"),
            args.get(3).is_some_and(|arg| arg == "--conflicting-base"),
        )?
        .buffer,
    )?;
    Ok(())
}
