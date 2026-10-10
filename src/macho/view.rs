//! Borrowed thin Mach-O header inspection without eagerly parsing commands or payloads.

use super::header::MachHeader;
use super::load_command::{LoadCommand, LoadCommands};
use crate::errors::FileParseError;
use crate::field::ByteOrder;

/// A thin Mach-O header backed by borrowed bytes.
///
/// Parsing allocates nothing and does not validate referenced commands or payloads.
/// For FAT input, select a thin slice with `super::MachO::fat_slice_ref` first.
/// All field offsets are relative to that thin slice.
pub struct MachHeaders<'a> {
    bytes: &'a [u8],
    /// Mach-O file header.
    pub header: MachHeader,
    order: ByteOrder,
}

impl<'a> MachHeaders<'a> {
    /// Parses only a thin Mach-O header, detecting word size and endianness.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FileParseError> {
        let magic: [u8; 4] = bytes
            .get(..4)
            .ok_or(FileParseError::BufferOverflow)?
            .try_into()
            .map_err(|_| FileParseError::BufferOverflow)?;
        let order = ByteOrder::from_macho_header_bytes(magic)?;
        let is_64bit = order.read_u32(bytes, 0)? == 0xfeedfacf;
        Ok(Self {
            bytes,
            header: MachHeader::parse(bytes, order, is_64bit)?,
            order,
        })
    }

    /// Returns the original borrowed thin image bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the file byte order.
    pub fn byte_order(&self) -> ByteOrder {
        self.order
    }

    /// Reads one load-command header without parsing its payload or allocating.
    ///
    /// Walks preceding command sizes and checks each extent against `sizeofcmds`.
    pub fn command(&self, index: usize) -> Result<LoadCommand, FileParseError> {
        if index >= self.header.ncmds.value as usize {
            return Err(FileParseError::BufferOverflow);
        }
        for (current, command) in self.commands().enumerate() {
            let command = command?;
            if current == index {
                return Ok(command);
            }
        }
        Err(FileParseError::BufferOverflow)
    }

    /// Iterates command headers once in file order, without allocation.
    pub fn commands(&self) -> LoadCommands<'a> {
        LoadCommands::new(
            self.bytes,
            self.order,
            if self.header.reserved.is_some() {
                32
            } else {
                28
            },
            self.header.sizeofcmds.value,
            self.header.ncmds.value,
        )
    }
}
