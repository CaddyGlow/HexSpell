//! Minimal PE32 / PE32+ seed, built from documented PE/COFF byte layouts.
//! No compiler-produced fixture or HexSpell serializer is used to create it.

pub fn image(is_64: bool) -> Vec<u8> {
    let mut bytes = vec![0; 0x800];
    fn u16_at(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn u32_at(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[..2].copy_from_slice(b"MZ");
    u32_at(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    let optional_size = if is_64 { 240 } else { 224 };
    u16_at(&mut bytes, 0x84, if is_64 { 0x8664 } else { 0x14c });
    u16_at(&mut bytes, 0x86, 3);
    u32_at(&mut bytes, 0x88, 0x1234_5678);
    u16_at(&mut bytes, 0x94, optional_size);
    u16_at(&mut bytes, 0x96, if is_64 { 0x22 } else { 0x102 });
    let optional = 0x98;
    u16_at(&mut bytes, optional, if is_64 { 0x20b } else { 0x10b });
    u32_at(&mut bytes, optional + 4, 512);
    u32_at(&mut bytes, optional + 8, 1024);
    u32_at(&mut bytes, optional + 16, 0x1000);
    u32_at(&mut bytes, optional + 20, 0x1000);
    if is_64 {
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    } else {
        u32_at(&mut bytes, optional + 24, 0x2000);
        u32_at(&mut bytes, optional + 28, 0x40_0000);
    }
    u32_at(&mut bytes, optional + 32, 0x1000);
    u32_at(&mut bytes, optional + 36, 0x200);
    u16_at(&mut bytes, optional + 40, 6);
    u16_at(&mut bytes, optional + 48, 6);
    u32_at(&mut bytes, optional + 56, 0x4000);
    u32_at(&mut bytes, optional + 60, 0x200);
    u16_at(&mut bytes, optional + 68, 3);
    let width = if is_64 { 8 } else { 4 };
    for (index, value) in [0x10_0000u32, 0x1000, 0x10_0000, 0x1000].iter().enumerate() {
        u32_at(&mut bytes, optional + 72 + index * width, *value);
    }
    u32_at(&mut bytes, optional + if is_64 { 108 } else { 92 }, 16);
    for (index, name) in [b".text\0\0\0", b".data\0\0\0", b".tail\0\0\0"]
        .iter()
        .enumerate()
    {
        let header = optional + optional_size as usize + index * 40;
        let raw = 0x200 + index * 0x200;
        bytes[header..header + 8].copy_from_slice(*name);
        u32_at(&mut bytes, header + 8, 173 + index as u32);
        u32_at(&mut bytes, header + 12, (index as u32 + 1) * 0x1000);
        u32_at(&mut bytes, header + 16, 0x200);
        u32_at(&mut bytes, header + 20, raw as u32);
        u32_at(
            &mut bytes,
            header + 36,
            if index == 0 { 0x6000_0020 } else { 0xc000_0040 },
        );
        for (pos, byte) in bytes[raw..raw + 0x200].iter_mut().enumerate() {
            *byte = (pos as u8).wrapping_mul(31).wrapping_add(17 + index as u8);
        }
    }
    bytes
}
