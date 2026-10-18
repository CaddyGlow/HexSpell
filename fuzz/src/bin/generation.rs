fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            hexspell_fuzz::generation(data);
        });
    }
}
