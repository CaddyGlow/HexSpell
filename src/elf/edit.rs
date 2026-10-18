//! Transactional ELF metadata edits with explicit build-ID consequences.
//!
//! Fixed-capacity replacements and append-only custom-section growth preserve
//! every allocated range and VA. Section-table rebuilding retains existing section
//! indices. Unknown references reject structural edits; dropping a session leaves
//! the caller untouched. Interpreter and selected dynamic strings can be replaced
//! only within verified capacity. Loader-owned notes cannot be replaced.
use super::ELF;
use crate::errors::{FileParseError, Result};
use alloc::vec::Vec;
use core::ops::Range;

/// Policy for note metadata which may contain a build ID.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BuildIdPolicy {
    /// Refuse modifications if any section or program header describes notes.
    #[default]
    Reject,
    /// Preserve note bytes and report that any existing build ID may be stale.
    PreserveStale,
    /// Remove GNU build-ID note identity while preserving note extents.
    Remove,
}

/// Consequences of a successful edit. Existing mapped virtual addresses stay fixed.
#[derive(Debug)]
pub struct EditReport {
    /// File ranges overwritten, including zero padding.
    pub changed_ranges: Vec<Range<usize>>,
    /// Whether note metadata was preserved and may contain a stale build ID.
    pub build_id_may_be_stale: bool,
    /// Original and replacement payload ranges; mapped addresses never change.
    pub moved_ranges: Vec<(Range<usize>, Range<usize>)>,
    /// Whether GNU build-ID notes were removed.
    pub build_id_removed: bool,
}

/// An isolated candidate; dropping it leaves the caller's image unchanged.
pub struct ElfEdit<'a> {
    source: &'a mut ELF,
    candidate: ELF,
    changed: Vec<Range<usize>>,
    has_notes: bool,
    policy: BuildIdPolicy,
    moved: Vec<(Range<usize>, Range<usize>)>,
}

fn unsupported() -> FileParseError {
    FileParseError::UnsupportedFeature(
        "ELF edit requires isolated owned metadata and fully modeled references".into(),
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

impl<'a> ElfEdit<'a> {
    /// Parse an owned snapshot. The caller's cached fields are not trusted.
    pub fn new(source: &'a mut ELF, policy: BuildIdPolicy) -> Result<Self> {
        let candidate = ELF::from_buffer(source.buffer.clone())?;
        let has_notes = candidate.section_headers.iter().any(|s| s.sh_type() == 7)
            || candidate.program_headers.iter().any(|p| p.p_type() == 4);
        Ok(Self {
            source,
            candidate,
            changed: Vec::new(),
            has_notes,
            policy,
            moved: Vec::new(),
        })
    }

    fn validate_range(&self, target: &Range<usize>, except: usize) -> Result<()> {
        let image = &self.candidate;
        if target.end > image.buffer.len() {
            return Err(FileParseError::BufferOverflow);
        }
        let h = &image.header;
        let header =
            0..usize::from(h.eh_size.value).max(if h.ei_class.value == 2 { 64 } else { 52 });
        let ph = range(
            h.ph_off.value,
            u64::from(h.ph_ent_size.value)
                .checked_mul(image.program_headers.len() as u64)
                .ok_or(FileParseError::BufferOverflow)?,
        )?;
        let sh = range(
            h.sh_off.value,
            u64::from(h.sh_ent_size.value)
                .checked_mul(image.section_headers.len() as u64)
                .ok_or(FileParseError::BufferOverflow)?,
        )?;
        if [header, ph, sh].iter().any(|r| overlaps(target, r))
            || self.changed.iter().any(|r| overlaps(target, r))
        {
            return Err(unsupported());
        }
        for (i, s) in image.section_headers.iter().enumerate() {
            if i != except
                && s.sh_type() != 8
                && overlaps(target, &range(s.sh_offset(), s.sh_size())?)
            {
                return Err(unsupported());
            }
        }
        for p in &image.program_headers {
            if overlaps(target, &range(p.p_offset(), p.p_filesz())?) {
                return Err(unsupported());
            }
        }
        Ok(())
    }

    fn custom(&self, index: usize) -> Result<&super::section::SectionHeaderEntry> {
        let s = self
            .candidate
            .section_headers
            .get(index)
            .ok_or(FileParseError::BufferOverflow)?;
        if index == 0 || s.sh_type() != 1 || s.sh_flags() != 0 || s.sh_addr() != 0 {
            return Err(unsupported());
        }
        Ok(s)
    }

    /// Replace a PROGBITS section with no flags or VA, padding to its existing size.
    /// The payload must not overlap headers, other sections, or program ranges.
    pub fn replace_custom_section(&mut self, index: usize, bytes: &[u8]) -> Result<()> {
        let s = self.custom(index)?;
        let target = range(s.sh_offset(), s.sh_size())?;
        self.validate_range(&target, index)?;
        if bytes.len() > target.len() {
            return Err(FileParseError::ValueTooLarge);
        }
        let destination = &mut self.candidate.buffer[target.clone()];
        destination.fill(0);
        destination[..bytes.len()].copy_from_slice(bytes);
        self.changed.push(target);
        Ok(())
    }

    /// Rename a custom section within its original string's capacity.
    /// Rejects shared strings, suffix aliases and referenced string tables.
    pub fn rename_custom_section(&mut self, index: usize, name: &str) -> Result<()> {
        self.custom(index)?;
        if name.as_bytes().contains(&0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let image = &self.candidate;
        let table_index = usize::from(image.header.sh_strndx.value);
        let table = image
            .section_headers
            .get(table_index)
            .ok_or(FileParseError::InvalidFileFormat)?;
        if table.sh_type() != 3
            || table.sh_flags() != 0
            || image
                .section_headers
                .iter()
                .any(|s| s.sh_link() as usize == table_index)
        {
            return Err(unsupported());
        }
        let table_range = range(table.sh_offset(), table.sh_size())?;
        let table_data = image
            .buffer
            .get(table_range.clone())
            .ok_or(FileParseError::BufferOverflow)?;
        let offset = image.section_headers[index].sh_name() as usize;
        // A boundary at the preceding NUL excludes aliases to a suffix of another string.
        if offset == 0 || table_data.get(offset - 1) != Some(&0) {
            return Err(unsupported());
        }
        let suffix = table_data
            .get(offset..)
            .ok_or(FileParseError::BufferOverflow)?;
        let length = suffix
            .iter()
            .position(|b| *b == 0)
            .ok_or(FileParseError::InvalidFileFormat)?;
        if name.len() > length {
            return Err(FileParseError::ValueTooLarge);
        }
        if image.section_headers.iter().enumerate().any(|(i, s)| {
            i != index && (offset..=offset + length).contains(&(s.sh_name() as usize))
        }) {
            return Err(unsupported());
        }
        let target = table_range.start + offset..table_range.start + offset + length + 1;
        self.validate_range(&target, table_index)?;
        let destination = &mut self.candidate.buffer[target.clone()];
        destination.fill(0);
        destination[..name.len()].copy_from_slice(name.as_bytes());
        self.changed.push(target);
        Ok(())
    }

    fn unreferenced(&self, index: usize) -> Result<()> {
        let image = &self.candidate;
        // Unknown tables may encode section indices, so structural changes fail closed.
        for (i, s) in image.section_headers.iter().enumerate() {
            if !matches!(s.sh_type(), 0..=9 | 11 | 14..=18 | 0x6fff_fff6 | 0x6fff_fffd..=0x6fff_ffff)
                || (i != index
                    && (s.sh_link() as usize == index
                        || (matches!(s.sh_type(), 4 | 9) || s.sh_flags() & 0x40 != 0)
                            && s.sh_info() as usize == index))
                || s.sh_type() == 17
                || s.sh_type() == 18
            {
                return Err(unsupported());
            }
        }
        let class = image.header.class()?;
        let order = image.byte_order()?;
        let stride = super::symbol::SymbolEntry::size_of(class);
        for section in image
            .section_headers
            .iter()
            .filter(|s| matches!(s.sh_type(), 2 | 11))
        {
            if section.sh_entsize() != stride as u64 || section.sh_size() % stride as u64 != 0 {
                return Err(FileParseError::InvalidFileFormat);
            }
            let bytes = range(section.sh_offset(), section.sh_size())?;
            if bytes.end > image.buffer.len() {
                return Err(FileParseError::BufferOverflow);
            }
            let symbols = super::symbol::SymbolEntry::parse_table(
                &image.buffer,
                bytes.start,
                bytes.len() / stride,
                class,
                order,
            )?;
            if symbols
                .iter()
                .any(|symbol| symbol.st_shndx() as usize == index)
            {
                return Err(unsupported());
            }
        }
        Ok(())
    }

    /// Grow isolated nonallocated custom data by appending a replacement payload.
    /// Existing file ranges and mapped addresses remain unchanged. Any section-index
    /// reference or unmodeled table rejects the operation before writes. Alignment
    /// must be a power of two no larger than the 4096-byte writer profile page.
    pub fn grow_custom_section(&mut self, index: usize, bytes: &[u8]) -> Result<()> {
        let s = self.custom(index)?;
        let old = range(s.sh_offset(), s.sh_size())?;
        self.validate_range(&old, index)?;
        self.unreferenced(index)?;
        let alignment = s.sh_addralign().max(1);
        if !alignment.is_power_of_two() || alignment > 4096 {
            return Err(unsupported());
        }
        let start = (self.candidate.buffer.len() as u64)
            .checked_add(alignment - 1)
            .ok_or(FileParseError::BufferOverflow)?
            & !(alignment - 1);
        let start = usize::try_from(start).map_err(|_| FileParseError::BufferOverflow)?;
        let end = start
            .checked_add(bytes.len())
            .ok_or(FileParseError::BufferOverflow)?;
        let order = self.candidate.byte_order()?;
        let mut buffer = self.candidate.buffer.clone();
        buffer.resize(start, 0);
        buffer.extend_from_slice(bytes);
        let s = &mut self.candidate.section_headers[index];
        s.sh_offset_mut()
            .update_with(&mut buffer, start as u64, order)?;
        s.sh_size_mut()
            .update_with(&mut buffer, bytes.len() as u64, order)?;
        self.candidate = ELF::from_buffer(buffer)?;
        self.changed.push(start..end);
        let header = range(
            self.candidate.header.sh_off.value
                + index as u64 * u64::from(self.candidate.header.sh_ent_size.value),
            u64::from(self.candidate.header.sh_ent_size.value),
        )?;
        self.changed.push(header);
        self.moved.push((old, start..end));
        Ok(())
    }

    /// Remove an unreferenced custom section, retaining all section indices.
    /// The inactive header and its old payload are zeroed; no mapped data moves.
    pub fn remove_custom_section(&mut self, index: usize) -> Result<()> {
        let s = self.custom(index)?;
        let target = range(s.sh_offset(), s.sh_size())?;
        self.validate_range(&target, index)?;
        self.unreferenced(index)?;
        let h = &self.candidate.header;
        let base = usize::try_from(h.sh_off.value)
            .map_err(|_| FileParseError::BufferOverflow)?
            .checked_add(
                index
                    .checked_mul(h.sh_ent_size.value as usize)
                    .ok_or(FileParseError::BufferOverflow)?,
            )
            .ok_or(FileParseError::BufferOverflow)?;
        let end = base
            .checked_add(h.sh_ent_size.value as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        let mut buffer = self.candidate.buffer.clone();
        buffer
            .get_mut(base..end)
            .ok_or(FileParseError::BufferOverflow)?
            .fill(0);
        buffer[target.clone()].fill(0);
        self.candidate = ELF::from_buffer(buffer)?;
        self.changed.extend([target, base..end]);
        Ok(())
    }

    /// Append nonallocated custom data and rebuild only the name and section tables.
    /// ELF32/64 and either byte order are supported; extended section numbering and
    /// references to the section-name string table are rejected.
    pub fn add_custom_section(&mut self, name: &str, bytes: &[u8]) -> Result<usize> {
        self.add_owned_section(name, bytes, 1, 1)
    }

    /// Append a caller-owned, nonallocated note section. Note records must be
    /// complete and four-byte aligned; this does not mutate loader-owned notes.
    pub fn add_note_section(&mut self, name: &str, bytes: &[u8]) -> Result<usize> {
        self.validate_note_payload(bytes)?;
        let index = self.add_owned_section(name, bytes, 7, 4)?;
        self.has_notes = true;
        Ok(index)
    }

    /// Replace an isolated nonallocated note section within existing capacity.
    /// The supplied complete note payload must have exactly the old section size.
    pub fn replace_note_section(&mut self, index: usize, bytes: &[u8]) -> Result<()> {
        self.validate_note_payload(bytes)?;
        let section = self
            .candidate
            .section_headers
            .get(index)
            .ok_or(FileParseError::BufferOverflow)?;
        if index == 0 || section.sh_type() != 7 || section.sh_flags() != 0 || section.sh_addr() != 0
        {
            return Err(unsupported());
        }
        let target = range(section.sh_offset(), section.sh_size())?;
        self.validate_range(&target, index)?;
        if target.len() != bytes.len() {
            return Err(FileParseError::ValueTooLarge);
        }
        self.candidate.buffer[target.clone()].copy_from_slice(bytes);
        self.changed.push(target);
        Ok(())
    }

    fn validate_note_payload(&self, bytes: &[u8]) -> Result<()> {
        let order = self.candidate.byte_order()?;
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            bytes
                .get(
                    cursor
                        ..cursor
                            .checked_add(12)
                            .ok_or(FileParseError::BufferOverflow)?,
                )
                .ok_or(FileParseError::InvalidFileFormat)?;
            let names = order.read_u32(bytes, cursor)? as usize;
            let desc = order.read_u32(bytes, cursor + 4)? as usize;
            cursor = cursor
                .checked_add(12)
                .and_then(|n| n.checked_add(names))
                .and_then(|n| n.checked_add(3))
                .map(|n| n & !3)
                .and_then(|n| n.checked_add(desc))
                .and_then(|n| n.checked_add(3))
                .map(|n| n & !3)
                .ok_or(FileParseError::BufferOverflow)?;
            if cursor > bytes.len() {
                return Err(FileParseError::InvalidFileFormat);
            }
        }
        Ok(())
    }

    fn add_owned_section(
        &mut self,
        name: &str,
        bytes: &[u8],
        kind: u32,
        alignment: usize,
    ) -> Result<usize> {
        if name.is_empty() || name.as_bytes().contains(&0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let image = &self.candidate;
        let index = image.section_headers.len();
        if index == 0 || index >= 0xfeff || image.header.sh_num.value as usize != index {
            return Err(unsupported());
        }
        let strings_index = image.header.sh_strndx.value as usize;
        let strings = image
            .section_headers
            .get(strings_index)
            .ok_or_else(unsupported)?;
        if strings.sh_type() != 3
            || strings.sh_flags() != 0
            || strings.sh_addr() != 0
            || image
                .section_headers
                .iter()
                .any(|s| s.sh_link() as usize == strings_index)
        {
            return Err(unsupported());
        }
        let old_strings = range(strings.sh_offset(), strings.sh_size())?;
        self.validate_range(&old_strings, strings_index)?;
        self.unreferenced(strings_index)?;
        let is64 = image.header.ei_class.value == 2;
        let stride = image.header.sh_ent_size.value as usize;
        if stride != if is64 { 64 } else { 40 } {
            return Err(unsupported());
        }
        let old_table = range(image.header.sh_off.value, (index * stride) as u64)?;
        let mut names = image
            .buffer
            .get(old_strings.clone())
            .ok_or(FileParseError::BufferOverflow)?
            .to_vec();
        let name_offset = u32::try_from(names.len()).map_err(|_| FileParseError::ValueTooLarge)?;
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        let order = image.byte_order()?;
        let mut buffer = image.buffer.clone();
        let padding = (alignment - buffer.len() % alignment) % alignment;
        buffer.resize(
            buffer
                .len()
                .checked_add(padding)
                .ok_or(FileParseError::BufferOverflow)?,
            0,
        );
        let payload = buffer.len();
        buffer.extend_from_slice(bytes);
        let names_at = buffer.len();
        buffer.extend_from_slice(&names);
        let padding = (8 - buffer.len() % 8) % 8;
        buffer.resize(buffer.len() + padding, 0);
        let table_at = buffer.len();
        buffer.extend_from_slice(
            image
                .buffer
                .get(old_table)
                .ok_or(FileParseError::BufferOverflow)?,
        );
        buffer.resize(buffer.len() + stride, 0);
        let mut write = |at: usize, value: u64| -> Result<()> {
            if is64 {
                order.write_u64(&mut buffer, at, value);
            } else {
                order.write_u32(
                    &mut buffer,
                    at,
                    u32::try_from(value).map_err(|_| FileParseError::ValueTooLarge)?,
                );
            }
            Ok(())
        };
        let strings_header = table_at + strings_index * stride;
        write(strings_header + if is64 { 24 } else { 16 }, names_at as u64)?;
        write(
            strings_header + if is64 { 32 } else { 20 },
            names.len() as u64,
        )?;
        let new_header = table_at + index * stride;
        write(new_header + if is64 { 24 } else { 16 }, payload as u64)?;
        write(new_header + if is64 { 32 } else { 20 }, bytes.len() as u64)?;
        write(new_header + if is64 { 48 } else { 32 }, alignment as u64)?;
        order.write_u32(&mut buffer, new_header, name_offset);
        order.write_u32(&mut buffer, new_header + 4, kind);
        let mut shoff = image.header.sh_off.clone();
        shoff.update_with(&mut buffer, table_at as u64, order)?;
        let mut count = image.header.sh_num.clone();
        count.update_with(&mut buffer, (index + 1) as u16, order)?;
        let candidate = ELF::from_buffer(buffer)?;
        self.changed.extend([
            payload..candidate.buffer.len(),
            shoff.offset..shoff.offset + shoff.size,
            count.offset..count.offset + count.size,
        ]);
        self.moved
            .push((old_strings, names_at..names_at + names.len()));
        self.candidate = candidate;
        Ok(index)
    }

    /// Replace the sole PT_INTERP string within its existing capacity.
    pub fn replace_interpreter(&mut self, value: &str) -> Result<()> {
        let image = &self.candidate;
        let mut headers = image.program_headers.iter().filter(|p| p.p_type() == 3);
        let p = headers.next().ok_or_else(unsupported)?;
        if headers.next().is_some() {
            return Err(unsupported());
        }
        let target = range(p.p_offset(), p.p_filesz())?;
        self.validate_metadata_range(&target, None)?;
        for other in &image.program_headers {
            if overlaps(&target, &range(other.p_offset(), other.p_filesz())?)
                && !matches!(other.p_type(), 1 | 3)
            {
                return Err(unsupported());
            }
        }
        self.replace_bounded_string(target, value)
    }

    /// Replace one NEEDED, SONAME or RUNPATH entry without growing `.dynstr`.
    /// Symbol-name aliases, suffix aliases, version tables and unmodeled consumers
    /// of the dynamic string table are rejected before changing bytes.
    pub fn replace_dynamic_string(
        &mut self,
        tag: u64,
        occurrence: usize,
        value: &str,
    ) -> Result<()> {
        if !matches!(tag, 1 | 14 | 29) {
            return Err(unsupported());
        }
        let image = &self.candidate;
        let dynamic_sections: Vec<_> = image
            .section_headers
            .iter()
            .enumerate()
            .filter(|(_, s)| s.sh_type() == 6)
            .collect();
        if dynamic_sections.len() != 1 {
            return Err(unsupported());
        }
        let (dynamic_index, dynamic) = dynamic_sections[0];
        let strings_index = dynamic.sh_link() as usize;
        let strings = image
            .section_headers
            .get(strings_index)
            .ok_or_else(unsupported)?;
        if strings.sh_type() != 3 {
            return Err(unsupported());
        }
        for (i, s) in image.section_headers.iter().enumerate() {
            if s.sh_link() as usize == strings_index && i != dynamic_index && s.sh_type() != 11 {
                return Err(unsupported());
            }
        }
        let table = image.dynamic()?.ok_or_else(unsupported)?;
        if table
            .entries
            .iter()
            .any(|entry| matches!(entry.tag(), 0x6fff_fffc..=0x6fff_ffff))
        {
            return Err(unsupported());
        }
        let entry = table
            .entries
            .iter()
            .filter(|e| e.tag() == tag)
            .nth(occurrence)
            .ok_or_else(unsupported)?;
        let data_range = range(strings.sh_offset(), strings.sh_size())?;
        self.validate_metadata_range(&data_range, Some(strings_index))?;
        let data = image
            .buffer
            .get(data_range.clone())
            .ok_or(FileParseError::BufferOverflow)?;
        let offset = usize::try_from(entry.value()).map_err(|_| FileParseError::BufferOverflow)?;
        if offset == 0 || data.get(offset - 1) != Some(&0) {
            return Err(unsupported());
        }
        let length = data
            .get(offset..)
            .ok_or(FileParseError::BufferOverflow)?
            .iter()
            .position(|b| *b == 0)
            .ok_or(FileParseError::InvalidFileFormat)?;
        let aliases = offset..=offset + length;
        // OS/processor-specific tags can carry additional string offsets.
        if table.entries.iter().any(|e| {
            e.tag() > 34
                && !matches!(
                    e.tag(),
                    0x6fff_fef5 | 0x6fff_fff0 | 0x6fff_fffb..=0x6fff_ffff
                )
        }) {
            return Err(unsupported());
        }
        if table.entries.iter().any(|e| {
            matches!(e.tag(), 1 | 14 | 15 | 29)
                && e.d_tag.offset != entry.d_tag.offset
                && usize::try_from(e.value()).is_ok_and(|n| aliases.contains(&n))
        }) {
            return Err(unsupported());
        }
        if let Some(symbols) = image.dynamic_symbols()? {
            if symbols
                .symbols
                .iter()
                .any(|s| aliases.contains(&(s.st_name() as usize)))
            {
                return Err(unsupported());
            }
        }
        self.replace_bounded_string(
            data_range.start + offset..data_range.start + offset + length + 1,
            value,
        )
    }

    fn validate_metadata_range(&self, target: &Range<usize>, owner: Option<usize>) -> Result<()> {
        let image = &self.candidate;
        let h = &image.header;
        let header =
            0..usize::from(h.eh_size.value).max(if h.ei_class.value == 2 { 64 } else { 52 });
        let ph = range(
            h.ph_off.value,
            u64::from(h.ph_ent_size.value) * image.program_headers.len() as u64,
        )?;
        let sh = range(
            h.sh_off.value,
            u64::from(h.sh_ent_size.value) * image.section_headers.len() as u64,
        )?;
        if [header, ph, sh].iter().any(|r| overlaps(r, target)) {
            return Err(unsupported());
        }
        for (i, section) in image.section_headers.iter().enumerate() {
            if section.sh_type() == 8 {
                continue;
            }
            let section_range = range(section.sh_offset(), section.sh_size())?;
            if overlaps(target, &section_range)
                && owner != Some(i)
                && !(owner.is_none() && section_range == *target && section.sh_type() == 1)
            {
                return Err(unsupported());
            }
        }
        Ok(())
    }

    fn replace_bounded_string(&mut self, target: Range<usize>, value: &str) -> Result<()> {
        if value.as_bytes().contains(&0) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let data = self
            .candidate
            .buffer
            .get(target.clone())
            .ok_or(FileParseError::BufferOverflow)?;
        let nul = data
            .iter()
            .position(|b| *b == 0)
            .ok_or(FileParseError::InvalidFileFormat)?;
        if data[nul..].iter().any(|b| *b != 0) || self.changed.iter().any(|r| overlaps(r, &target))
        {
            return Err(unsupported());
        }
        if value.len() >= data.len() {
            return Err(FileParseError::ValueTooLarge);
        }
        let data = &mut self.candidate.buffer[target.clone()];
        data.fill(0);
        data[..value.len()].copy_from_slice(value.as_bytes());
        self.changed.push(target);
        Ok(())
    }

    /// Validate and swap the candidate into the caller. An error preserves the source.
    pub fn commit(mut self) -> Result<EditReport> {
        if !self.changed.is_empty() && self.has_notes && self.policy == BuildIdPolicy::Reject {
            return Err(FileParseError::UnsupportedFeature(
                "ELF note metadata requires an explicit PreserveStale build-ID policy".into(),
            ));
        }
        let mut removed = false;
        if !self.changed.is_empty() && self.policy == BuildIdPolicy::Remove {
            let order = self.candidate.byte_order()?;
            let mut notes = Vec::new();
            for s in &self.candidate.section_headers {
                if s.sh_type() == 7 {
                    notes.push(range(s.sh_offset(), s.sh_size())?);
                }
            }
            for p in &self.candidate.program_headers {
                if p.p_type() == 4 {
                    notes.push(range(p.p_offset(), p.p_filesz())?);
                }
            }
            for target in notes {
                let payload = self
                    .candidate
                    .buffer
                    .get(target.clone())
                    .ok_or(FileParseError::BufferOverflow)?;
                self.validate_note_payload(payload)?;
                let table = super::note::NoteTable::parse(
                    &self.candidate.buffer,
                    target.start,
                    target.len(),
                    order,
                )?;
                for mut note in table.entries {
                    if note.name == b"GNU\0" && note.n_type.value == 3 {
                        // Changing the owner hides build-ID identity without inventing a
                        // new GNU note type or shifting subsequent note records.
                        let at = note.n_type.offset + 4;
                        self.candidate.buffer[at..at + 4].copy_from_slice(b"HXS\0");
                        note.n_type
                            .update_with(&mut self.candidate.buffer, 0, order)?;
                        self.changed.push(note.n_type.offset..at + 4);
                        removed = true;
                    }
                }
            }
        }
        let candidate = ELF::from_buffer(self.candidate.buffer)?;
        let stale =
            self.has_notes && !self.changed.is_empty() && self.policy != BuildIdPolicy::Remove;
        *self.source = candidate;
        Ok(EditReport {
            changed_ranges: self.changed,
            build_id_may_be_stale: stale,
            moved_ranges: self.moved,
            build_id_removed: removed,
        })
    }
}
