use std::error::Error;
use std::hint::black_box;
use std::path::Path;
use std::time::{Duration, Instant};

use hexspell::pe::{
    header::{OptionalHeader, PEType},
    view::PeHeaders,
    PE,
};
use object::Object;

type BenchResult<T> = Result<T, Box<dyn Error>>;

fn measure(
    mut action: impl FnMut() -> BenchResult<usize>,
    duration: Duration,
    rounds: usize,
) -> BenchResult<(u64, u64, u64, usize)> {
    let warmup_start = Instant::now();
    for _ in 0..3 {
        black_box(action()?);
    }
    let warmup_cost = (warmup_start.elapsed().as_nanos() / 3).max(1);
    let batch = (duration.as_nanos() / 100 / warmup_cost).clamp(1, 64) as usize;
    let mut samples = Vec::with_capacity(rounds);
    let mut total_iterations = 0;
    for _ in 0..rounds {
        let start = Instant::now();
        let mut count = 0usize;
        loop {
            // Amortize clock calls for sub-microsecond borrowed parsers.
            for _ in 0..batch {
                black_box(action()?);
            }
            count += batch;
            if start.elapsed() >= duration {
                break;
            }
        }
        samples.push((start.elapsed().as_nanos() / count as u128) as u64);
        total_iterations += count;
    }
    samples.sort_unstable();
    Ok((
        samples[0],
        ((samples[(rounds - 1) / 2] as u128 + samples[rounds / 2] as u128) / 2) as u64,
        samples[rounds - 1],
        total_iterations,
    ))
}

fn csv(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn run(path: &Path, milliseconds: u64, rounds: usize) -> BenchResult<()> {
    // File I/O and Python startup are outside every timed loop.
    let buffer = std::fs::read(path)?;
    // Derive metadata without requiring HexSpell's eager relocation parser to
    // accept the input before the other parsers get a chance to run.
    let headers = PeHeaders::parse(&buffer)?;
    let optional = OptionalHeader::parse(&buffer, headers.optional)?;
    let kind = optional.pe_type()?;
    let sections = headers.coff.number_of_sections.value as usize;
    let directories = optional
        .data_directories
        .iter()
        .take(optional.active_data_directory_count())
        .filter(|entry| entry.virtual_address.value != 0 && entry.size.value != 0)
        .count();
    let duration = Duration::from_millis(milliseconds);
    let name = path
        .file_name()
        .ok_or("missing filename")?
        .to_string_lossy();
    let mut failed = false;
    let mut benchmark =
        |library: &str, scope: &str, action: &mut dyn FnMut() -> BenchResult<usize>| {
            let result = (|| {
                if action()? != sections {
                    return Err("parser section count disagrees with corpus metadata".into());
                }
                measure(action, duration, rounds)
            })();
            match result {
                Ok((min, median, max, iterations)) => println!(
                    "{},{},{},{},{},{},{},{},{},{},{},ok",
                    csv(&name),
                    buffer.len(),
                    if matches!(kind, PEType::PE32) {
                        "PE32"
                    } else {
                        "PE32+"
                    },
                    sections,
                    directories,
                    library,
                    scope,
                    min,
                    median,
                    max,
                    iterations
                ),
                Err(error) => {
                    failed = true;
                    eprintln!("{} / {library} / {scope}: {error}", path.display());
                    println!(
                        "{},{},{},{},{},{},{},,,,,error",
                        csv(&name),
                        buffer.len(),
                        if matches!(kind, PEType::PE32) {
                            "PE32"
                        } else {
                            "PE32+"
                        },
                        sections,
                        directories,
                        library,
                        scope
                    );
                }
            }
        };
    benchmark("hexspell", "borrowed_headers", &mut || {
        let headers = PeHeaders::parse(black_box(&buffer))?;
        black_box(&headers);
        Ok(headers.coff.number_of_sections.value as usize)
    });
    benchmark(
        "hexspell",
        "borrowed_all_header_fields_and_sections",
        &mut || {
            let headers = PeHeaders::parse(black_box(&buffer))?;
            black_box(OptionalHeader::parse(&buffer, headers.optional)?);
            for index in 0..headers.coff.number_of_sections.value as usize {
                black_box(headers.section(index)?);
            }
            Ok(headers.coff.number_of_sections.value as usize)
        },
    );
    benchmark(
        "hexspell",
        "owned_default_parse_including_clone",
        &mut || {
            let image = PE::from_buffer(black_box(&buffer).clone())?;
            black_box(&image);
            Ok(image.sections.len())
        },
    );
    benchmark("object", "borrowed_pe_headers_and_sections", &mut || {
        let count = match kind {
            PEType::PE32 => {
                let image = object::read::pe::PeFile32::parse(black_box(buffer.as_slice()))?;
                black_box(&image);
                image.sections().count()
            }
            PEType::PE32Plus => {
                let image = object::read::pe::PeFile64::parse(black_box(buffer.as_slice()))?;
                black_box(&image);
                image.sections().count()
            }
        };
        Ok(count)
    });
    benchmark("goblin", "borrowed_default_parse", &mut || {
        let image = goblin::pe::PE::parse(black_box(&buffer))?;
        black_box(&image);
        Ok(image.sections.len())
    });
    benchmark(
        "hexspell",
        "owned_parse_and_supported_directories",
        &mut || {
            let image = PE::from_buffer(black_box(&buffer).clone())?;
            // Same supported directory requests as Python's supported_directories scope.
            black_box(image.imports()?);
            black_box(image.exports()?);
            black_box(image.resources()?);
            black_box(image.tls()?);
            black_box(image.debug_directory()?);
            black_box(image.load_config()?);
            black_box(image.bound_imports()?);
            black_box(image.delay_imports()?);
            if matches!(kind, PEType::PE32Plus) {
                black_box(image.exceptions()?);
            }
            black_box(&image);
            Ok(image.sections.len())
        },
    );
    if failed {
        return Err("one or more parser scopes failed; see CSV status column".into());
    }
    Ok(())
}

fn main() -> BenchResult<()> {
    let mut args = std::env::args().skip(1);
    let corpus = args
        .next()
        .ok_or("usage: hexspell-pe-bench CORPUS_DIR [MILLISECONDS_PER_ROUND=100] [ROUNDS=7]")?;
    let milliseconds = args
        .next()
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(100u64);
    let rounds = args
        .next()
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(7usize);
    if milliseconds == 0 || rounds == 0 {
        return Err("duration and rounds must be positive".into());
    }
    let mut files: Vec<_> = std::fs::read_dir(&corpus)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<_, _>>()?;
    files.retain(|path| {
        path.extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("dll"))
    });
    files.sort();
    if files.is_empty() {
        return Err("corpus has no .exe or .dll files".into());
    }
    eprintln!("benchmark harness {}; HexSpell path dependency; goblin 0.10.7; object 0.40.0; {rounds} rounds x {milliseconds} ms; {} files", env!("CARGO_PKG_VERSION"), files.len());
    println!("file,bytes,format,sections,directories,library,scope,min_ns,median_ns,max_ns,iterations,status");
    let mut failed = false;
    for path in files {
        if let Err(error) = run(&path, milliseconds, rounds) {
            eprintln!("{}: {error}", path.display());
            // The individual scopes print their own failures. If metadata
            // itself could not be read, preserve an explicit file-level row.
            if let Ok(buffer) = std::fs::read(&path) {
                if PeHeaders::parse(&buffer)
                    .and_then(|headers| OptionalHeader::parse(&buffer, headers.optional))
                    .is_err()
                {
                    println!(
                        "{},{},unknown,,,hexspell,metadata,,,,,error",
                        csv(&path.file_name().unwrap_or_default().to_string_lossy()),
                        buffer.len()
                    );
                }
            }
            failed = true;
        }
    }
    if failed {
        return Err("one or more corpus files could not be parsed by HexSpell".into());
    }
    Ok(())
}
