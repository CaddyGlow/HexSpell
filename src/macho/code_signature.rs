//! Opaque `LC_CODE_SIGNATURE` blobs and layout preparation for external signers.
//!
//! Reading exposes the command fields and raw bytes. Writing reserves the final
//! layout before hashing, then installs exactly that many signature bytes. Neither
//! operation creates or validates CodeDirectories, CMS signatures or trust chains.
use super::{
    load_command::{LinkeditDataCommand, LC_CODE_SIGNATURE},
    MachO,
};
use crate::{
    errors::{FileParseError, Result},
    field::Field,
};

impl<B: core::ops::Deref<Target = [u8]>> MachO<B> {
    /// Reads the unique `LC_CODE_SIGNATURE` command and bounds-checks its blob.
    /// Empty reservations are exposed too; duplicate commands are rejected.
    pub fn code_signature(&self) -> Result<Option<LinkeditDataCommand>> {
        let mut commands = self
            .load_commands
            .iter()
            .filter(|c| c.cmd.value == LC_CODE_SIGNATURE);
        let Some(command) = commands.next() else {
            return Ok(None);
        };
        if commands.next().is_some() || command.cmdsize.value != 16 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let order = self.byte_order();
        let offset = command.cmd.offset;
        let dataoff = order.read_u32(&self.buffer, offset + 8)?;
        let datasize = order.read_u32(&self.buffer, offset + 12)?;
        let end = (dataoff as usize)
            .checked_add(datasize as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        if end > self.buffer.len() {
            return Err(FileParseError::BufferOverflow);
        }
        Ok(Some(LinkeditDataCommand {
            dataoff: Field::new(dataoff, offset + 8, 4),
            datasize: Field::new(datasize, offset + 12, 4),
        }))
    }
    /// Returns the opaque signature bytes, including any reserved zero bytes.
    pub fn code_signature_data(&self) -> Result<Option<&[u8]>> {
        let Some(command) = self.code_signature()? else {
            return Ok(None);
        };
        let start = command.dataoff.value as usize;
        Ok(Some(
            &self.buffer[start..start + command.datasize.value as usize],
        ))
    }
}

#[cfg(feature = "write")]
mod edit {
    use super::*;
    use crate::field::ByteOrder;
    use crate::macho::edit::{MachOEdit, SignaturePolicy};
    use alloc::vec::Vec;
    use core::ops::Range;

    /// Final byte locations an external signer must use before creating its blob.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CodeSignatureLayout {
        /// All file bytes preceding the signature, after load-command/segment updates.
        pub signing_range: Range<usize>,
        /// Exact reserved blob extent. Writing never changes this capacity.
        pub signature_range: Range<usize>,
    }
    fn unsupported() -> FileParseError {
        FileParseError::UnsupportedFeature("Mach-O signature editing requires a thin little-endian x86-64/arm64 image, isolated final __LINKEDIT and unused command padding".into())
    }
    fn range(start: u64, size: u64) -> Result<Range<u64>> {
        Ok(start
            ..start
                .checked_add(size)
                .ok_or(FileParseError::ValueTooLarge)?)
    }
    fn overlaps(a: &Range<u64>, b: &Range<u64>) -> bool {
        a.start < b.end && b.start < a.end
    }
    fn validate_existing(image: &MachO) -> Result<()> {
        if image.header.reserved.is_none()
            || image.byte_order() != ByteOrder::Little
            || !matches!(image.header.cpu_type.value, 0x1000007 | 0x100000c)
        {
            return Err(unsupported());
        }
        let Some(command) = image.code_signature()? else {
            return Ok(());
        };
        let target = range(
            u64::from(command.dataoff.value),
            u64::from(command.datasize.value),
        )?;
        if !target.is_empty() && !target.start.is_multiple_of(16) {
            return Err(unsupported());
        }
        let mut owners = 0;
        for segment in &image.segments {
            let file = range(segment.fileoff(), segment.filesize())?;
            if file.end > image.buffer.len() as u64 || segment.filesize() > segment.vmsize() {
                return Err(unsupported());
            }
            if overlaps(&file, &target) {
                if segment.name() != "__LINKEDIT"
                    || file.start > target.start
                    || file.end != target.end
                {
                    return Err(unsupported());
                }
                owners += 1;
            }
        }
        if !target.is_empty() && owners != 1 {
            return Err(unsupported());
        }
        Ok(())
    }
    impl MachO {
        /// Reserves an aligned EOF blob and updates `LC_CODE_SIGNATURE` and `__LINKEDIT`.
        ///
        /// Reuses an existing isolated final reservation of equal size without changing bytes;
        /// otherwise replaces it. No existing payload moves.
        /// Hash the returned signing range only AFTER this succeeds, then install a blob
        /// of exactly `size` bytes with `write_code_signature`. Changing size requires a
        /// new reservation and digest. Zero size, unknown reference-bearing commands,
        /// command-padding aliases and overlapping mappings are rejected transactionally.
        pub fn reserve_code_signature(&mut self, size: u32) -> Result<CodeSignatureLayout> {
            if size == 0 {
                return Err(FileParseError::InvalidFileFormat);
            }
            let mut candidate = MachO::from_buffer(self.buffer.clone())?;
            if candidate.header.reserved.is_none()
                || candidate.byte_order() != ByteOrder::Little
                || !matches!(candidate.header.cpu_type.value, 0x1000007 | 0x100000c)
            {
                return Err(unsupported());
            }
            if let Some(command) = candidate.code_signature()? {
                validate_existing(&candidate)?;
                let start = command.dataoff.value as usize;
                if command.datasize.value == size {
                    // Preserve platform-specific segment rounding when capacity fits.
                    let mut checked = MachO::from_buffer(candidate.buffer.clone())?;
                    checked.remove_code_signature()?;
                    let end = start
                        .checked_add(size as usize)
                        .ok_or(FileParseError::ValueTooLarge)?;
                    *self = candidate;
                    return Ok(CodeSignatureLayout {
                        signing_range: 0..start,
                        signature_range: start..end,
                    });
                }
                candidate.remove_code_signature()?;
            }
            let command_start = 32usize
                .checked_add(candidate.header.sizeofcmds.value as usize)
                .ok_or(FileParseError::ValueTooLarge)?;
            let command_end = command_start
                .checked_add(16)
                .ok_or(FileParseError::ValueTooLarge)?;
            if candidate
                .buffer
                .get(command_start..command_end)
                .is_none_or(|p| p.iter().any(|b| *b != 0))
            {
                return Err(unsupported());
            }
            super::super::edit::validate_signature_padding(
                &mut candidate,
                &(command_start..command_end),
            )?;
            for section in &candidate.sections {
                if !matches!(section.flags() & 0xff, 1 | 0xc | 0x12)
                    && overlaps(
                        &range(u64::from(section.offset()), section.size())?,
                        &(command_start as u64..command_end as u64),
                    )
                {
                    return Err(unsupported());
                }
                if overlaps(
                    &range(u64::from(section.reloff()), u64::from(section.nreloc()) * 8)?,
                    &(command_start as u64..command_end as u64),
                ) {
                    return Err(unsupported());
                }
            }
            let owners: Vec<_> = candidate
                .segments
                .iter()
                .enumerate()
                .filter(|(_, s)| s.name() == "__LINKEDIT")
                .map(|(i, _)| i)
                .collect();
            if owners.len() != 1 {
                return Err(unsupported());
            }
            let index = owners[0];
            let segment = &candidate.segments[index];
            let old_file = range(segment.fileoff(), segment.filesize())?;
            if old_file.end != candidate.buffer.len() as u64
                || old_file.start < command_end as u64
                || segment.filesize() > segment.vmsize()
            {
                return Err(unsupported());
            }
            let start = candidate
                .buffer
                .len()
                .checked_add(15)
                .ok_or(FileParseError::ValueTooLarge)?
                & !15;
            let end = start
                .checked_add(size as usize)
                .ok_or(FileParseError::ValueTooLarge)?;
            u32::try_from(end).map_err(|_| FileParseError::ValueTooLarge)?;
            let file_size = (end as u64)
                .checked_sub(segment.fileoff())
                .ok_or(FileParseError::ValueTooLarge)?;
            let page = if candidate.header.cpu_type.value == 0x100000c {
                16384
            } else {
                4096
            };
            let vm_size = (file_size
                .checked_add(page - 1)
                .ok_or(FileParseError::ValueTooLarge)?
                & !(page - 1))
                .max(segment.vmsize());
            let new_vm = range(segment.vmaddr(), vm_size)?;
            let new_file = segment.fileoff()..end as u64;
            let mut header_owner = 0;
            for (other_index, other) in candidate.segments.iter().enumerate() {
                if other_index == index {
                    continue;
                }
                let file = range(other.fileoff(), other.filesize())?;
                if file.end > candidate.buffer.len() as u64 || other.filesize() > other.vmsize() {
                    return Err(unsupported());
                }
                if overlaps(&file, &(command_start as u64..command_end as u64)) && file.start != 0 {
                    return Err(unsupported());
                }
                if overlaps(&new_file, &file)
                    || overlaps(&new_vm, &range(other.vmaddr(), other.vmsize())?)
                {
                    return Err(unsupported());
                }
                if file.start == 0 && file.end >= command_end as u64 {
                    header_owner += 1;
                }
            }
            if header_owner != 1 {
                return Err(unsupported());
            }
            let order = candidate.byte_order();
            let mut buffer = candidate.buffer.clone();
            buffer.resize(end, 0);
            for (at, value) in [
                (command_start, LC_CODE_SIGNATURE),
                (command_start + 4, 16),
                (command_start + 8, start as u32),
                (command_start + 12, size),
            ] {
                order.write_u32(&mut buffer, at, value);
            }
            order.write_u32(
                &mut buffer,
                16,
                candidate
                    .header
                    .ncmds
                    .value
                    .checked_add(1)
                    .ok_or(FileParseError::ValueTooLarge)?,
            );
            order.write_u32(
                &mut buffer,
                20,
                candidate
                    .header
                    .sizeofcmds
                    .value
                    .checked_add(16)
                    .ok_or(FileParseError::ValueTooLarge)?,
            );
            candidate.segments[index]
                .filesize_mut()
                .update_with(&mut buffer, file_size, order)?;
            candidate.segments[index]
                .vmsize_mut()
                .update_with(&mut buffer, vm_size, order)?;
            let candidate = MachO::from_buffer(buffer)?;
            candidate.code_signature()?;
            *self = candidate;
            Ok(CodeSignatureLayout {
                signing_range: 0..start,
                signature_range: start..end,
            })
        }
        /// Installs opaque signature bytes into an existing reservation of exactly equal size.
        ///
        /// Leaves every byte outside the blob unchanged, including hashed header metadata.
        /// Does not validate blob structure, page hashes, CMS content, entitlements or trust.
        pub fn write_code_signature(&mut self, blob: &[u8]) -> Result<()> {
            let mut candidate = MachO::from_buffer(self.buffer.clone())?;
            let command = candidate
                .code_signature()?
                .ok_or(FileParseError::InvalidFileFormat)?;
            if blob.is_empty() || blob.len() != command.datasize.value as usize {
                return Err(FileParseError::InvalidFileFormat);
            }
            let start = command.dataoff.value as usize;
            // Reuse the strip preflight to prove that this blob is isolated and unaliased.
            let mut checked = MachO::from_buffer(candidate.buffer.clone())?;
            validate_existing(&candidate)?;
            checked.remove_code_signature()?;
            candidate.buffer[start..start + blob.len()].copy_from_slice(blob);
            *self = candidate;
            Ok(())
        }
        /// Removes an isolated final signature and its load command transactionally.
        /// Other file offsets and mapped addresses remain unchanged; re-sign before use.
        /// An image without a signature is unchanged.
        pub fn remove_code_signature(&mut self) -> Result<()> {
            let mut candidate = MachO::from_buffer(self.buffer.clone())?;
            if candidate.code_signature()?.is_none() {
                return Ok(());
            }
            validate_existing(&candidate)?;
            MachOEdit::with_signature_policy(&mut candidate, SignaturePolicy::Strip)?.commit()?;
            *self = candidate;
            Ok(())
        }
    }
}
#[cfg(feature = "write")]
pub use edit::CodeSignatureLayout;
