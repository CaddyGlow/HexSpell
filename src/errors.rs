//! Error types shared across the crate.
//!
//! Binary parsing is prone to a variety of failures ranging from truncated
//! data to unsupported features. The [`FileParseError`] enum captures these
//! cases in a single place so that all modules can communicate problems in a
//! consistent manner. For convenience a `Result` alias is provided as well.

use alloc::string::String;

use core::fmt;
#[cfg(feature = "std")]
use std::io;

#[derive(Debug)]
pub enum FileParseError {
    /// Underlying I/O failure (read/write).
    #[cfg(feature = "std")]
    Io(io::Error),
    /// Magic bytes or structural invariant does not match the expected format.
    InvalidFileFormat,
    /// Read or write would extend past the end of the buffer.
    BufferOverflow,
    /// Numeric value does not fit in the on-disk field width.
    ValueTooLarge,
    /// Requested capability is not implemented yet.
    UnsupportedFeature(String),
}

impl fmt::Display for FileParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            FileParseError::Io(err) => write!(f, "I/O error: {err}"),
            FileParseError::InvalidFileFormat => write!(f, "Invalid file format."),
            FileParseError::BufferOverflow => write!(f, "Data out of bounds."),
            FileParseError::ValueTooLarge => write!(f, "Value exceeds field size."),
            FileParseError::UnsupportedFeature(feature) => {
                write!(f, "Unsupported feature: {feature}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl From<io::Error> for FileParseError {
    fn from(err: io::Error) -> Self {
        FileParseError::Io(err)
    }
}
impl core::error::Error for FileParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            #[cfg(feature = "std")]
            FileParseError::Io(err) => Some(err),
            _ => None,
        }
    }
}
/// Convenience alias used by all format parsers.
pub type Result<T> = core::result::Result<T, FileParseError>;
