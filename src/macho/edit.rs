//! Transactional Mach-O custom data and command-string edits.
//!
//! Fixed-capacity replacements, checked payload growth, and custom-segment additions
//! preserve existing virtual addresses. Signed images require an explicit strip
//! policy and external re-signing. Unknown command references reject payload edits.
//! FAT slices can be rebuilt transactionally when a selected thin image grows.
use super::{
    load_command::{LC_CODE_SIGNATURE, LC_SEGMENT, LC_SEGMENT_64},
    MachO,
};
use crate::errors::{FileParseError, Result};
use alloc::vec::Vec;
use core::ops::Range;

/// Consequences of a successful edit; existing virtual addresses stay fixed.
#[derive(Debug)]
pub struct EditReport {
    /// File ranges overwritten, including padding.
    pub changed_ranges: Vec<Range<usize>>,
    /// Existing virtual addresses are preserved by every supported operation.
    pub virtual_addresses_preserved: bool,
    /// A prior signature was stripped; external signing is required for native use.
    pub requires_signing: bool,
    /// Original and replacement custom payload file ranges.
    pub moved_ranges: Vec<(Range<usize>, Range<usize>)>,
}
/// An isolated candidate; dropping it leaves the caller's image unchanged.
pub struct MachOEdit<'a> {
    source: &'a mut MachO,
    candidate: MachO,
    changed: Vec<Range<usize>>,
    requires_signing: bool,
    moved: Vec<(Range<usize>, Range<usize>)>,
}
/// Signature handling for transactional edits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SignaturePolicy {
    /// Reject any LC_CODE_SIGNATURE command, including an empty command.
    #[default]
    Reject,
    /// Remove the command and its signature bytes. Sign the result before native use.
    Strip,
}
fn unsupported() -> FileParseError {
    FileParseError::UnsupportedFeature(
        "Mach-O edit requires unsigned isolated __CUSTOM regular data".into(),
    )
}
fn range(offset: u64, size: u64) -> Result<Range<usize>> {
    let start = usize::try_from(offset).map_err(|_| FileParseError::BufferOverflow)?;
    let size = usize::try_from(size).map_err(|_| FileParseError::BufferOverflow)?;
    Ok(start
        ..start
            .checked_add(size)
            .ok_or(FileParseError::BufferOverflow)?)
}
fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}
impl<'a> MachOEdit<'a> {
    /// Reparse a snapshot; reject signed images before planning any writes.
    pub fn new(source: &'a mut MachO) -> Result<Self> {
        Self::with_signature_policy(source, SignaturePolicy::Reject)
    }

    /// Reparse a snapshot and apply the explicit signature policy transactionally.
    pub fn with_signature_policy(source: &'a mut MachO, policy: SignaturePolicy) -> Result<Self> {
        let mut candidate = MachO::from_buffer(source.buffer.clone())?;
        let signatures: Vec<_> = candidate
            .load_commands
            .iter()
            .filter(|c| c.cmd.value == LC_CODE_SIGNATURE)
            .collect();
        if signatures.len() > 1 {
            return Err(unsupported());
        }
        let mut changed = Vec::new();
        let requires_signing = !signatures.is_empty();
        if let Some(command) = signatures.first() {
            if policy == SignaturePolicy::Reject {
                return Err(unsupported());
            }
            if command.cmdsize.value != 16 {
                return Err(FileParseError::InvalidFileFormat);
            }
            let order = candidate.byte_order();
            let base = command.cmd.offset;
            let target = range(
                u64::from(order.read_u32(&candidate.buffer, base + 8)?),
                u64::from(order.read_u32(&candidate.buffer, base + 12)?),
            )?;
            let header_size = if candidate.header.reserved.is_some() {
                32
            } else {
                28
            };
            let commands_end = header_size + candidate.header.sizeofcmds.value as usize;
            if (!target.is_empty() && target.start < commands_end)
                || target.end > candidate.buffer.len()
            {
                return Err(unsupported());
            }
            // Only a final __LINKEDIT signature is owned by this removal profile.
            let mut owned = None;
            for (index, segment) in candidate.segments.iter().enumerate() {
                let mapped = range(segment.fileoff(), segment.filesize())?;
                if segment.name() == "__LINKEDIT"
                    && target.start >= mapped.start
                    && target.end <= mapped.end
                    && owned.replace(index).is_some()
                {
                    return Err(unsupported());
                }
            }
            for section in &candidate.sections {
                if !matches!(section.flags() & 0xff, 1 | 0xc | 0x12)
                    && overlaps(
                        &target,
                        &range(u64::from(section.offset()), section.size())?,
                    )
                {
                    return Err(unsupported());
                }
                if overlaps(
                    &target,
                    &range(u64::from(section.reloff()), u64::from(section.nreloc()) * 8)?,
                ) {
                    return Err(unsupported());
                }
            }
            if !target.is_empty() && (target.end != candidate.buffer.len() || owned.is_none()) {
                return Err(unsupported());
            }
            let mut buffer = candidate.buffer.clone();
            if !target.is_empty() {
                let index = owned.ok_or_else(unsupported)?;
                let file_size = (target.start as u64)
                    .checked_sub(candidate.segments[index].fileoff())
                    .ok_or(FileParseError::BufferOverflow)?;
                let page = if candidate.header.cpu_type.value == 0x100000c {
                    16384u64
                } else {
                    4096
                };
                let virtual_size = file_size
                    .checked_add(page - 1)
                    .map(|n| n & !(page - 1))
                    .ok_or(FileParseError::BufferOverflow)?
                    .min(candidate.segments[index].vmsize());
                if virtual_size < file_size {
                    return Err(unsupported());
                }
                let metadata = match &candidate.segments[index] {
                    super::segment::SegmentEntry::Segment32(s) => {
                        s.segname.offset - 8..s.segname.offset - 8 + 56
                    }
                    super::segment::SegmentEntry::Segment64(s) => {
                        s.segname.offset - 8..s.segname.offset - 8 + 72
                    }
                };
                changed.push(metadata);
                candidate.segments[index].filesize_mut().update_with(
                    &mut buffer,
                    file_size,
                    order,
                )?;
                candidate.segments[index].vmsize_mut().update_with(
                    &mut buffer,
                    virtual_size,
                    order,
                )?;
            }
            buffer.copy_within(base + 16..commands_end, base);
            buffer[commands_end - 16..commands_end].fill(0);
            if !target.is_empty() {
                buffer.truncate(target.start);
            }
            order.write_u32(&mut buffer, 16, candidate.header.ncmds.value - 1);
            order.write_u32(&mut buffer, 20, candidate.header.sizeofcmds.value - 16);
            candidate = MachO::from_buffer(buffer)?;
            changed.extend([base..commands_end, target]);
        }
        let edit = Self {
            source,
            candidate,
            changed,
            requires_signing,
            moved: Vec::new(),
        };
        if requires_signing {
            if let Some(signature) = edit.changed.last() {
                edit.validate_commands(signature)?;
            }
        }
        Ok(edit)
    }
    fn validate_commands(&self, target: &Range<usize>) -> Result<()> {
        let image = &self.candidate;
        if image.load_commands.iter().any(|c| {
            !matches!(
                c.cmd.value,
                LC_SEGMENT
                    | LC_SEGMENT_64
                    | 0x2
                    | 0x80000028
                    | 0x32
                    | 0x24
                    | 0x1b
                    | 0x2a
                    | 0xe
                    | 0xc
                    | 0xd
                    | 0x80000018
                    | 0x8000001f
                    | 0x20
                    | 0x8000001c
                    | 0x1c
                    | 0xb
                    | 0x22
                    | 0x80000022
                    | 0x80000033
                    | 0x80000034
                    | 0x26
                    | 0x29
                    | 0x2b
                    | 0x2e
            )
        }) {
            return Err(unsupported());
        }
        if image
            .load_commands
            .iter()
            .filter(|c| c.cmd.value == 0x80000034)
            .count()
            > 1
        {
            return Err(unsupported());
        }
        let order = image.byte_order();
        for command in &image.load_commands {
            let base = command.cmd.offset;
            let mut referenced = Vec::new();
            match command.cmd.value {
                0x80000033 | 0x80000034 | 0x26 | 0x29 | 0x2b | 0x2e => {
                    if command.cmdsize.value != 16 {
                        return Err(FileParseError::InvalidFileFormat);
                    }
                    referenced.push(range(
                        u64::from(order.read_u32(&image.buffer, base + 8)?),
                        u64::from(order.read_u32(&image.buffer, base + 12)?),
                    )?);
                }
                0x22 | 0x80000022 => {
                    if command.cmdsize.value != 48 {
                        return Err(FileParseError::InvalidFileFormat);
                    }
                    // Legacy opcode streams describe writes outside their own file
                    // ranges. Until those locations are inventoried, fail closed.
                    for at in [12, 20, 28, 36] {
                        if order.read_u32(&image.buffer, base + at)? != 0 {
                            return Err(unsupported());
                        }
                    }
                    for at in (8..48).step_by(8) {
                        referenced.push(range(
                            u64::from(order.read_u32(&image.buffer, base + at)?),
                            u64::from(order.read_u32(&image.buffer, base + at + 4)?),
                        )?);
                    }
                }
                0xb => {
                    if command.cmdsize.value != 80 {
                        return Err(FileParseError::InvalidFileFormat);
                    }
                    if order.read_u32(&image.buffer, base + 68)? != 0
                        || order.read_u32(&image.buffer, base + 76)? != 0
                    {
                        return Err(unsupported());
                    }
                    let is64 = image.header.reserved.is_some();
                    for (at, stride) in [
                        (32, 8u64),
                        (40, if is64 { 56 } else { 52 }),
                        (48, 4),
                        (56, 4),
                        (64, 8),
                        (72, 8),
                    ] {
                        referenced.push(range(
                            u64::from(order.read_u32(&image.buffer, base + at)?),
                            u64::from(order.read_u32(&image.buffer, base + at + 4)?) * stride,
                        )?);
                    }
                }
                _ => {}
            }
            if referenced
                .iter()
                .any(|r| !r.is_empty() && (r.end > image.buffer.len() || overlaps(r, target)))
            {
                return Err(unsupported());
            }
            if command.cmd.value == 2 {
                if command.cmdsize.value < 24 {
                    return Err(FileParseError::InvalidFileFormat);
                }
                let base = command.cmd.offset;
                let symoff = order.read_u32(&image.buffer, base + 8)?;
                let nsyms = order.read_u32(&image.buffer, base + 12)?;
                let stroff = order.read_u32(&image.buffer, base + 16)?;
                let strsize = order.read_u32(&image.buffer, base + 20)?;
                let symbols = range(
                    u64::from(symoff),
                    u64::from(nsyms)
                        * if image.header.reserved.is_some() {
                            16
                        } else {
                            12
                        },
                )?;
                let strings = range(u64::from(stroff), u64::from(strsize))?;
                if (!symbols.is_empty() && symbols.end > image.buffer.len())
                    || (!strings.is_empty() && strings.end > image.buffer.len())
                {
                    return Err(FileParseError::BufferOverflow);
                }
                if overlaps(target, &symbols) || overlaps(target, &strings) {
                    return Err(unsupported());
                }
            }
        }
        self.validate_chained_slots(target)
    }

    fn validate_chained_slots(&self, target: &Range<usize>) -> Result<()> {
        use super::dyld::{decode_chained_pointer, ChainedPointer};
        let image = &self.candidate;
        let Some(fixups) = image.chained_fixups()? else {
            return Ok(());
        };
        if image.header.reserved.is_none() || image.byte_order() != crate::field::ByteOrder::Little
        {
            return Err(unsupported());
        }
        let mut mappings = image
            .segments
            .iter()
            .filter(|s| s.fileoff() == 0 && s.filesize() >= 32);
        let base = mappings.next().ok_or_else(unsupported)?.vmaddr();
        if mappings.next().is_some() {
            return Err(unsupported());
        }
        // Monotone chains cannot loop, but aliased segment mappings must not
        // cause unbounded repeated traversal of the same file bytes.
        let mut remaining = image.buffer.len() / 8;
        for starts in &fixups.segments {
            let segment = image
                .segments
                .get(starts.segment_index)
                .ok_or_else(unsupported)?;
            let file = range(segment.fileoff(), segment.filesize())?;
            if base.checked_add(starts.segment_offset) != Some(segment.vmaddr())
                || segment.filesize() > segment.vmsize()
                || file.end > image.buffer.len()
            {
                return Err(unsupported());
            }
            let page_size = u64::from(starts.page_size);
            for (page, start) in starts.page_starts.iter().enumerate() {
                let page_start = (page as u64)
                    .checked_mul(page_size)
                    .ok_or(FileParseError::BufferOverflow)?;
                if page_start >= segment.vmsize() {
                    return Err(unsupported());
                }
                let Some(start) = start else {
                    continue;
                };
                let page_end = page_start
                    .checked_add(page_size)
                    .ok_or(FileParseError::BufferOverflow)?;
                let mut offset = page_start
                    .checked_add(u64::from(*start))
                    .ok_or(FileParseError::BufferOverflow)?;
                loop {
                    remaining = remaining.checked_sub(1).ok_or_else(unsupported)?;
                    let end = offset
                        .checked_add(8)
                        .ok_or(FileParseError::BufferOverflow)?;
                    if end > page_end || end > segment.filesize() {
                        return Err(unsupported());
                    }
                    let slot = range(
                        segment
                            .fileoff()
                            .checked_add(offset)
                            .ok_or(FileParseError::BufferOverflow)?,
                        8,
                    )?;
                    if overlaps(target, &slot) {
                        return Err(unsupported());
                    }
                    let pointer = image.byte_order().read_u64(&image.buffer, slot.start)?;
                    let next = match decode_chained_pointer(pointer)? {
                        ChainedPointer::Bind { ordinal, next, .. } => {
                            if ordinal as usize >= fixups.imports.len() {
                                return Err(unsupported());
                            }
                            next
                        }
                        ChainedPointer::Rebase { next, .. } => next,
                    };
                    if next == 0 {
                        break;
                    }
                    if next < 8 {
                        return Err(unsupported());
                    }
                    offset = offset
                        .checked_add(u64::from(next))
                        .ok_or(FileParseError::BufferOverflow)?;
                }
            }
        }
        Ok(())
    }
    /// Replace an isolated regular section in `__CUSTOM`, preserving its capacity.
    /// Images with other command types are rejected because those commands may
    /// contain file ranges referencing the payload (including opaque commands).
    pub fn replace_custom_section(&mut self, index: usize, bytes: &[u8]) -> Result<()> {
        let image = &self.candidate;
        let section = image
            .sections
            .get(index)
            .ok_or(FileParseError::BufferOverflow)?;
        if section.segment_name() != "__CUSTOM" || section.flags() != 0 || section.nreloc() != 0 {
            return Err(unsupported());
        }
        let target = range(u64::from(section.offset()), section.size())?;
        let mut owners = 0;
        for segment in &image.segments {
            let mapped = range(segment.fileoff(), segment.filesize())?;
            if overlaps(&target, &mapped)
                || (target.is_empty() && target.start >= mapped.start && target.start <= mapped.end)
            {
                let delta = u64::from(section.offset())
                    .checked_sub(segment.fileoff())
                    .ok_or_else(unsupported)?;
                if segment.name() != "__CUSTOM"
                    || target.start < mapped.start
                    || target.end > mapped.end
                    || segment.vmaddr().checked_add(delta) != Some(section.addr())
                    || delta
                        .checked_add(section.size())
                        .is_none_or(|end| end > segment.vmsize())
                {
                    return Err(unsupported());
                }
                owners += 1;
            }
        }
        if owners != 1 {
            return Err(unsupported());
        }
        self.validate_commands(&target)?;
        let commands_end = image.load_commands.iter().try_fold(0usize, |end, c| {
            Ok::<_, FileParseError>(
                end.max(
                    c.cmd
                        .offset
                        .checked_add(c.cmdsize.value as usize)
                        .ok_or(FileParseError::BufferOverflow)?,
                ),
            )
        })?;
        if target.start < commands_end.max(32) || self.changed.iter().any(|r| overlaps(r, &target))
        {
            return Err(unsupported());
        }
        for (i, s) in image.sections.iter().enumerate() {
            if i != index
                && !matches!(s.flags() & 0xff, 1 | 0xc | 0x12)
                && overlaps(&target, &range(u64::from(s.offset()), s.size())?)
            {
                return Err(unsupported());
            }
            if overlaps(
                &target,
                &range(u64::from(s.reloff()), u64::from(s.nreloc()) * 8)?,
            ) {
                return Err(unsupported());
            }
        }
        if bytes.len() > target.len() {
            return Err(FileParseError::ValueTooLarge);
        }
        let destination = self
            .candidate
            .buffer
            .get_mut(target.clone())
            .ok_or(FileParseError::BufferOverflow)?;
        destination.fill(0);
        destination[..bytes.len()].copy_from_slice(bytes);
        self.changed.push(target);
        Ok(())
    }
    /// Replace a dylib install/dependency name or RPATH within its command capacity.
    /// Existing trailing padding must be zero; no command or file offsets change.
    pub fn replace_command_string(&mut self, index: usize, value: &str) -> Result<()> {
        if value.as_bytes().contains(&0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let image = &self.candidate;
        let command = image
            .load_commands
            .get(index)
            .ok_or(FileParseError::BufferOverflow)?;
        let minimum = match command.cmd.value {
            0xc | 0xd | 0x80000018 | 0x8000001f | 0x20 => 24,
            0x1c | 0x8000001c => 12,
            _ => return Err(unsupported()),
        };
        let base = command.cmd.offset;
        let size = command.cmdsize.value as usize;
        if size < minimum {
            return Err(FileParseError::InvalidFileFormat);
        }
        let offset = image.byte_order().read_u32(&image.buffer, base + 8)? as usize;
        if offset < minimum || offset >= size {
            return Err(FileParseError::InvalidFileFormat);
        }
        let target = base
            .checked_add(offset)
            .ok_or(FileParseError::BufferOverflow)?
            ..base
                .checked_add(size)
                .ok_or(FileParseError::BufferOverflow)?;
        if self.changed.iter().any(|r| overlaps(r, &target)) {
            return Err(unsupported());
        }
        self.validate_commands(&target)?;
        let current = image
            .buffer
            .get(target.clone())
            .ok_or(FileParseError::BufferOverflow)?;
        let nul = current
            .iter()
            .position(|b| *b == 0)
            .ok_or(FileParseError::InvalidFileFormat)?;
        if current[nul..].iter().any(|b| *b != 0) {
            return Err(unsupported());
        }
        if value.len() >= current.len() {
            return Err(FileParseError::ValueTooLarge);
        }
        // Command space must not double as a section payload or relocation array.
        for section in &image.sections {
            if !matches!(section.flags() & 0xff, 1 | 0xc | 0x12)
                && overlaps(
                    &target,
                    &range(u64::from(section.offset()), section.size())?,
                )
            {
                return Err(unsupported());
            }
            if overlaps(
                &target,
                &range(u64::from(section.reloff()), u64::from(section.nreloc()) * 8)?,
            ) {
                return Err(unsupported());
            }
        }
        let destination = &mut self.candidate.buffer[target.clone()];
        destination.fill(0);
        destination[..value.len()].copy_from_slice(value.as_bytes());
        self.changed.push(target);
        Ok(())
    }
    /// Grow the sole section in an isolated `__CUSTOM` segment, preserving its VA.
    /// Verified zero padding is consumed first, extending the segment's file size
    /// within its virtual capacity when needed. Only a final custom segment may
    /// move to appended page-aligned file space. Virtual overlap is rejected.
    pub fn grow_custom_section(&mut self, index: usize, bytes: &[u8]) -> Result<()> {
        // Reuse the complete reference and ownership checks without writing.
        let old_changed = self.changed.len();
        let snapshot = self.candidate.buffer.clone();
        self.replace_custom_section(index, &[])?;
        self.candidate = MachO::from_buffer(snapshot)?;
        self.changed.truncate(old_changed);
        let image = &self.candidate;
        let section = &image.sections[index];
        let old_range = range(u64::from(section.offset()), section.size())?;
        let owners: Vec<_> = image
            .segments
            .iter()
            .enumerate()
            .filter(|(_, seg)| {
                seg.name() == "__CUSTOM"
                    && seg.fileoff() == u64::from(section.offset())
                    && seg.vmaddr() == section.addr()
                    && seg.nsects() == 1
            })
            .collect();
        if owners.len() != 1 || bytes.is_empty() {
            return Err(unsupported());
        }
        let (owner_index, owner) = owners[0];
        let mut capacity = range(owner.fileoff(), owner.vmsize())?;
        capacity.end = capacity.end.min(image.buffer.len());
        for (i, segment) in image.segments.iter().enumerate() {
            if i != owner_index && segment.fileoff() > owner.fileoff() && segment.filesize() != 0 {
                capacity.end = capacity.end.min(
                    usize::try_from(segment.fileoff())
                        .map_err(|_| FileParseError::BufferOverflow)?,
                );
            }
        }
        let expanded = range(u64::from(section.offset()), bytes.len() as u64)?;
        if expanded.end <= capacity.end && bytes.len() as u64 <= owner.vmsize() {
            self.validate_commands(&expanded)?;
            for (i, segment) in image.segments.iter().enumerate() {
                if i != owner_index
                    && overlaps(&expanded, &range(segment.fileoff(), segment.filesize())?)
                {
                    return Err(unsupported());
                }
            }
            for (i, other) in image.sections.iter().enumerate() {
                if i != index
                    && !matches!(other.flags() & 0xff, 1 | 0xc | 0x12)
                    && overlaps(&expanded, &range(u64::from(other.offset()), other.size())?)
                {
                    return Err(unsupported());
                }
                if overlaps(
                    &expanded,
                    &range(u64::from(other.reloff()), u64::from(other.nreloc()) * 8)?,
                ) {
                    return Err(unsupported());
                }
            }
            if expanded.end > old_range.end
                && image
                    .buffer
                    .get(old_range.end..expanded.end)
                    .ok_or(FileParseError::BufferOverflow)?
                    .iter()
                    .any(|b| *b != 0)
            {
                return Err(unsupported());
            }
            let order = image.byte_order();
            let mut buffer = image.buffer.clone();
            buffer
                .get_mut(expanded.clone())
                .ok_or(FileParseError::BufferOverflow)?
                .copy_from_slice(bytes);
            let new_file_size = owner.filesize().max(bytes.len() as u64);
            let segment_header = match owner {
                super::segment::SegmentEntry::Segment32(s) => {
                    s.segname.offset - 8..s.segname.offset - 8 + 56
                }
                super::segment::SegmentEntry::Segment64(s) => {
                    s.segname.offset - 8..s.segname.offset - 8 + 72
                }
            };
            self.candidate.segments[owner_index]
                .filesize_mut()
                .update_with(&mut buffer, new_file_size, order)?;
            let section = &mut self.candidate.sections[index];
            let header = match &*section {
                super::section::SectionEntry::Section32(s) => {
                    s.sectname.offset..s.sectname.offset + 68
                }
                super::section::SectionEntry::Section64(s) => {
                    s.sectname.offset..s.sectname.offset + 80
                }
            };
            section
                .size_mut()
                .update_with(&mut buffer, bytes.len() as u64, order)?;
            self.candidate = MachO::from_buffer(buffer)?;
            self.changed.extend([expanded, header, segment_header]);
            return Ok(());
        }
        // Moving a payload beyond a following segment would violate the native
        // file/virtual segment order. Only a final custom segment may relocate.
        if image.segments.iter().enumerate().any(|(i, seg)| {
            i != owner_index && seg.fileoff() >= owner.fileoff() && seg.filesize() != 0
        }) {
            return Err(unsupported());
        }
        // Relocating the segment also relocates padding outside the section.
        // Runtime chains may legally have nodes in that padding.
        self.validate_commands(&range(owner.fileoff(), owner.filesize())?)?;
        let page = if image.header.cpu_type.value == 0x100000c {
            16384u64
        } else {
            4096
        };
        let align = |n: u64| {
            n.checked_add(page - 1)
                .map(|n| n & !(page - 1))
                .ok_or(FileParseError::BufferOverflow)
        };
        let size = align(bytes.len() as u64)?;
        let va_end = owner
            .vmaddr()
            .checked_add(size)
            .ok_or(FileParseError::BufferOverflow)?;
        for (i, segment) in image.segments.iter().enumerate() {
            if i != owner_index
                && owner.vmaddr()
                    < segment
                        .vmaddr()
                        .checked_add(segment.vmsize())
                        .ok_or(FileParseError::BufferOverflow)?
                && segment.vmaddr() < va_end
            {
                return Err(unsupported());
            }
        }
        let offset = align(image.buffer.len() as u64)?;
        let end = usize::try_from(
            offset
                .checked_add(size)
                .ok_or(FileParseError::BufferOverflow)?,
        )
        .map_err(|_| FileParseError::BufferOverflow)?;
        let offset32 = u32::try_from(offset).map_err(|_| FileParseError::ValueTooLarge)?;
        let order = image.byte_order();
        let mut buffer = image.buffer.clone();
        buffer.resize(end, 0);
        buffer[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
        let segment_header = match &self.candidate.segments[owner_index] {
            super::segment::SegmentEntry::Segment32(s) => {
                s.segname.offset - 8..s.segname.offset - 8 + 56
            }
            super::segment::SegmentEntry::Segment64(s) => {
                s.segname.offset - 8..s.segname.offset - 8 + 72
            }
        };
        let section_header = match &self.candidate.sections[index] {
            super::section::SectionEntry::Section32(s) => s.sectname.offset..s.sectname.offset + 68,
            super::section::SectionEntry::Section64(s) => s.sectname.offset..s.sectname.offset + 80,
        };
        let segment = &mut self.candidate.segments[owner_index];
        segment
            .fileoff_mut()
            .update_with(&mut buffer, offset, order)?;
        segment
            .filesize_mut()
            .update_with(&mut buffer, size, order)?;
        segment.vmsize_mut().update_with(&mut buffer, size, order)?;
        let section = &mut self.candidate.sections[index];
        section
            .size_mut()
            .update_with(&mut buffer, bytes.len() as u64, order)?;
        match section {
            super::section::SectionEntry::Section32(s) => {
                s.offset.update_with(&mut buffer, offset32, order)?
            }
            super::section::SectionEntry::Section64(s) => {
                s.offset.update_with(&mut buffer, offset32, order)?
            }
        }
        self.candidate = MachO::from_buffer(buffer)?;
        self.changed
            .extend([offset as usize..end, segment_header, section_header]);
        self.moved
            .push((old_range, offset as usize..offset as usize + bytes.len()));
        Ok(())
    }

    /// Append a regular section in a new `__CUSTOM` segment using zero-filled
    /// load-command capacity. Existing file ranges and virtual addresses stay fixed.
    /// The new segment receives a fresh page-aligned VA after all mapped segments.
    /// Images with an existing __LINKEDIT must reserve __CUSTOM at construction;
    /// adding beyond __LINKEDIT would violate native segment file ordering.
    pub fn add_custom_section(&mut self, name: &str, bytes: &[u8]) -> Result<usize> {
        if name.is_empty() || name.len() > 16 || name.as_bytes().contains(&0) || bytes.is_empty() {
            return Err(FileParseError::InvalidFileFormat);
        }
        let image = &self.candidate;
        if image.header.reserved.is_none()
            || !matches!(image.header.cpu_type.value, 0x1000007 | 0x100000c)
            || image.segments.iter().any(|seg| seg.name() == "__CUSTOM")
            || image.segments.iter().any(|seg| seg.name() == "__LINKEDIT")
        {
            return Err(unsupported());
        }
        let base = 32usize
            .checked_add(image.header.sizeofcmds.value as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        let end = base
            .checked_add(152)
            .ok_or(FileParseError::BufferOverflow)?;
        // A section or referenced linkedit range may never double as header slack.
        self.validate_commands(&(base..end))?;
        if image
            .buffer
            .get(base..end)
            .ok_or_else(unsupported)?
            .iter()
            .any(|b| *b != 0)
        {
            return Err(unsupported());
        }
        for section in &image.sections {
            if !matches!(section.flags() & 0xff, 1 | 0xc | 0x12)
                && overlaps(
                    &(base..end),
                    &range(u64::from(section.offset()), section.size())?,
                )
            {
                return Err(unsupported());
            }
            if overlaps(
                &(base..end),
                &range(u64::from(section.reloff()), u64::from(section.nreloc()) * 8)?,
            ) {
                return Err(unsupported());
            }
        }
        for segment in &image.segments {
            if segment.fileoff() != 0
                && overlaps(&(base..end), &range(segment.fileoff(), segment.filesize())?)
            {
                return Err(unsupported());
            }
        }
        let page = if image.header.cpu_type.value == 0x100000c {
            16384u64
        } else {
            4096
        };
        let align = |value: u64| {
            value
                .checked_add(page - 1)
                .map(|n| n & !(page - 1))
                .ok_or(FileParseError::BufferOverflow)
        };
        let vmaddr = align(image.segments.iter().try_fold(0u64, |max, s| {
            s.vmaddr()
                .checked_add(s.vmsize())
                .map(|n| max.max(n))
                .ok_or(FileParseError::BufferOverflow)
        })?)?;
        let fileoff = align(image.buffer.len() as u64)?;
        let filesize = align(bytes.len() as u64)?;
        vmaddr
            .checked_add(filesize)
            .ok_or(FileParseError::BufferOverflow)?;
        let new_end = usize::try_from(
            fileoff
                .checked_add(filesize)
                .ok_or(FileParseError::BufferOverflow)?,
        )
        .map_err(|_| FileParseError::BufferOverflow)?;
        let section_offset = u32::try_from(fileoff).map_err(|_| FileParseError::ValueTooLarge)?;
        let order = image.byte_order();
        let mut buffer = image.buffer.clone();
        buffer.resize(new_end, 0);
        buffer[fileoff as usize..fileoff as usize + bytes.len()].copy_from_slice(bytes);
        order.write_u32(&mut buffer, base, LC_SEGMENT_64);
        order.write_u32(&mut buffer, base + 4, 152);
        buffer[base + 8..base + 16].copy_from_slice(b"__CUSTOM");
        order.write_u64(&mut buffer, base + 24, vmaddr);
        order.write_u64(&mut buffer, base + 32, filesize);
        order.write_u64(&mut buffer, base + 40, fileoff);
        order.write_u64(&mut buffer, base + 48, filesize);
        order.write_u32(&mut buffer, base + 56, 1);
        order.write_u32(&mut buffer, base + 60, 1);
        order.write_u32(&mut buffer, base + 64, 1);
        let section = base + 72;
        buffer[section..section + name.len()].copy_from_slice(name.as_bytes());
        buffer[section + 16..section + 24].copy_from_slice(b"__CUSTOM");
        order.write_u64(&mut buffer, section + 32, vmaddr);
        order.write_u64(&mut buffer, section + 40, bytes.len() as u64);
        order.write_u32(&mut buffer, section + 48, section_offset);
        order.write_u32(
            &mut buffer,
            16,
            image
                .header
                .ncmds
                .value
                .checked_add(1)
                .ok_or(FileParseError::BufferOverflow)?,
        );
        order.write_u32(
            &mut buffer,
            20,
            image
                .header
                .sizeofcmds
                .value
                .checked_add(152)
                .ok_or(FileParseError::BufferOverflow)?,
        );
        let index = image.sections.len();
        self.candidate = MachO::from_buffer(buffer)?;
        self.changed
            .extend([16..24, base..end, fileoff as usize..new_end]);
        Ok(index)
    }

    /// Reparse and swap the candidate. An error preserves the caller's image.
    pub fn commit(self) -> Result<EditReport> {
        let candidate = MachO::from_buffer(self.candidate.buffer)?;
        *self.source = candidate;
        Ok(EditReport {
            changed_ranges: self.changed,
            virtual_addresses_preserved: true,
            requires_signing: self.requires_signing,
            moved_ranges: self.moved,
        })
    }
}

/// Edit a selected FAT slice transactionally, preserving the entire container layout.
///
/// Since every supported operation preserves capacity, architecture metadata,
/// alignment, padding and all other slice bytes remain byte-for-byte identical.
/// Report ranges are relative to the selected thin image, not the FAT container.
/// Signed slices are rejected. Thin inputs must use `MachOEdit` directly.
pub fn edit_fat_slice<F>(buffer: &mut [u8], index: usize, plan: F) -> Result<EditReport>
where
    F: FnOnce(&mut MachOEdit<'_>) -> Result<()>,
{
    let fat = super::fat::FatHeader::parse(buffer)?.ok_or(FileParseError::InvalidFileFormat)?;
    let arch = fat
        .arches
        .get(index)
        .ok_or(FileParseError::BufferOverflow)?;
    let target = range(arch.offset, arch.size)?;
    let mut image = MachO::from_buffer(fat.slice_ref(buffer, arch)?.to_vec())?;
    if image.header.cpu_type.value != arch.cpu_type
        || image.header.cpu_subtype.value != arch.cpu_subtype
    {
        return Err(FileParseError::InvalidFileFormat);
    }
    // Reject aliased slice ranges before changing any container bytes.
    let header_size = 8usize
        .checked_add(
            fat.arches
                .len()
                .checked_mul(if fat.is_64 { 32 } else { 20 })
                .ok_or(FileParseError::BufferOverflow)?,
        )
        .ok_or(FileParseError::BufferOverflow)?;
    if target.start < header_size {
        return Err(FileParseError::InvalidFileFormat);
    }
    for (i, other) in fat.arches.iter().enumerate() {
        if i != index && overlaps(&target, &range(other.offset, other.size)?) {
            return Err(FileParseError::InvalidFileFormat);
        }
    }
    let mut edit = MachOEdit::new(&mut image)?;
    plan(&mut edit)?;
    let report = edit.commit()?;
    if image.buffer.len() != target.len() {
        return Err(unsupported());
    }
    buffer
        .get_mut(target)
        .ok_or(FileParseError::BufferOverflow)?
        .copy_from_slice(&image.buffer);
    Ok(report)
}

/// Edit and rebuild a FAT container when the selected thin image changes length.
/// Every other thin slice and CPU/subtype/alignment value is preserved. Container
/// padding and slice file offsets are rebuilt; report ranges remain thin-relative.
pub fn rebuild_fat_slice<F>(
    buffer: &mut Vec<u8>,
    index: usize,
    policy: SignaturePolicy,
    plan: F,
) -> Result<EditReport>
where
    F: FnOnce(&mut MachOEdit<'_>) -> Result<()>,
{
    let fat = super::fat::FatHeader::parse(buffer)?.ok_or(FileParseError::InvalidFileFormat)?;
    if index >= fat.arches.len() {
        return Err(FileParseError::BufferOverflow);
    }
    let table_end = 8usize
        .checked_add(
            fat.arches
                .len()
                .checked_mul(if fat.is_64 { 32 } else { 20 })
                .ok_or(FileParseError::BufferOverflow)?,
        )
        .ok_or(FileParseError::BufferOverflow)?;
    for (i, arch) in fat.arches.iter().enumerate() {
        let target = range(arch.offset, arch.size)?;
        if target.start < table_end
            || target.end > buffer.len()
            || arch.align > 30
            || target.start % (1usize << arch.align) != 0
        {
            return Err(unsupported());
        }
        for other in &fat.arches[..i] {
            if overlaps(&target, &range(other.offset, other.size)?) {
                return Err(unsupported());
            }
        }
    }
    let arch = &fat.arches[index];
    let mut image = MachO::from_buffer(fat.slice_ref(buffer, arch)?.to_vec())?;
    if image.header.cpu_type.value != arch.cpu_type
        || image.header.cpu_subtype.value != arch.cpu_subtype
    {
        return Err(FileParseError::InvalidFileFormat);
    }
    let mut edit = MachOEdit::with_signature_policy(&mut image, policy)?;
    plan(&mut edit)?;
    let report = edit.commit()?;
    let slices: Vec<_> = fat
        .arches
        .iter()
        .enumerate()
        .map(|(i, arch)| {
            Ok((
                arch.clone(),
                if i == index {
                    image.buffer.as_slice()
                } else {
                    fat.slice_ref(buffer, arch)?
                },
            ))
        })
        .collect::<Result<_>>()?;
    // Preflight the writer arithmetic, which expects representable slice extents.
    let mut cursor = table_end;
    for (arch, data) in &slices {
        let align = 1usize << arch.align;
        cursor = cursor
            .checked_add(align - 1)
            .map(|n| n & !(align - 1))
            .and_then(|n| n.checked_add(data.len()))
            .ok_or(FileParseError::BufferOverflow)?;
    }
    let rebuilt = super::fat::FatHeader::build(&slices)?;
    *buffer = rebuilt;
    Ok(report)
}

// Signature reservations may consume only padding not referenced by loader metadata.
pub(super) fn validate_signature_padding(image: &mut MachO, target: &Range<usize>) -> Result<()> {
    for command in &image.load_commands {
        if command.cmd.value == super::load_command::LC_MAIN {
            if command.cmdsize.value != 24 {
                return Err(FileParseError::InvalidFileFormat);
            }
            // Executable entry bytes need not belong to a section.
            let entry = image
                .byte_order()
                .read_u64(&image.buffer, command.cmd.offset + 8)?;
            if (target.start as u64..target.end as u64).contains(&entry) {
                return Err(unsupported());
            }
        }
    }
    MachOEdit::new(image)?.validate_commands(target)
}
