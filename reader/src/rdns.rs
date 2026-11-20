use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::path::Path;

use lzma_rust2::LzmaReader;

use crate::{Result, corrupt, ensure};

pub const MAGIC: &[u8; 4] = b"RDN1";
pub const LZMA_SETTINGS: [u32; 3] = [4, 0, 0];
pub const WINDOW: u32 = 1 << 21;

pub const PLAIN: u8 = 1;
pub const PADDED: u8 = 5;
pub const HEX: u8 = 9;
pub const SHORT_HEX: u8 = 13;
pub const DECIMAL: u8 = 17;
pub const BASE36: u8 = 22;
pub const SELECTORS: u8 = 5;
pub const END: u8 = 0x1e;
pub const SEPARATOR: u8 = 0x1f;

pub struct Run {
    pub start: u32,
    pub end: u32,
    pub template: Vec<u8>,
}

pub struct Database {
    bytes: Vec<u8>,
    firsts: Vec<u32>,
    offsets: Vec<usize>,
}

pub fn select(ip: u32, selector: u8) -> i64 {
    i64::from(match selector {
        0 => ip,
        1 => ip & 0xff_ffff,
        2 => ip & 0xffff,
        3 => ip & 0xff,
        _ => (ip >> 8) & 0xff,
    })
}

fn base36(mut value: i64, width: usize, out: &mut Vec<u8>) {
    let start = out.len();
    loop {
        out.push(b"0123456789abcdefghijklmnopqrstuvwxyz"[value.rem_euclid(36) as usize]);
        value = value.div_euclid(36);
        if value <= 0 && out.len() - start >= width {
            break;
        }
    }
    out[start..].reverse();
}

fn affine(template: &[u8], position: &mut usize, code: u8, ip: u32, out: &mut Vec<u8>) {
    let width =
        usize::from(template.get(*position).map_or(0, |&byte| byte.saturating_sub(b'0')));
    *position += 1;
    let rest = template.get(*position..).unwrap_or_default();
    let length = rest.iter().position(|&byte| byte == END).unwrap_or(rest.len());
    let text = std::str::from_utf8(&rest[..length]).unwrap_or_default();
    let offset: i64 = text.parse().unwrap_or(0);
    *position += length + 1;
    let value = select(ip, (code - DECIMAL) % SELECTORS) + offset;
    if code >= BASE36 {
        return base36(value, width, out);
    }
    let _ = write!(out, "{value:0width$}");
}

pub fn render(template: &[u8], ip: u32, out: &mut Vec<u8>) {
    let octets = ip.to_be_bytes();
    let mut position = 0;
    while let Some(&byte) = template.get(position) {
        position += 1;
        let octet = octets[(byte.wrapping_sub(1) % 4) as usize];
        match byte {
            1..=4 => _ = write!(out, "{octet}"),
            5..=8 => _ = write!(out, "{octet:03}"),
            9..=12 => _ = write!(out, "{octet:02x}"),
            13..=16 => _ = write!(out, "{octet:x}"),
            17..=26 => affine(template, &mut position, byte, ip, out),
            _ => out.push(byte),
        }
    }
}

pub fn names(template: &[u8], ip: u32) -> Vec<String> {
    template
        .split(|&byte| byte == SEPARATOR)
        .map(|part| {
            let mut out = Vec::new();
            render(part, ip, &mut out);
            String::from_utf8_lossy(&out).into_owned()
        })
        .collect()
}

pub fn push_varint(out: &mut Vec<u8>, mut value: u32) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn varint(bytes: &[u8], position: &mut usize) -> Result<u32> {
    let mut value = 0u32;
    for shift in (0..35).step_by(7) {
        let byte = *bytes.get(*position).ok_or_else(|| corrupt("truncated varint"))?;
        *position += 1;
        value |= u32::from(byte & 0x7f).checked_shl(shift).unwrap_or(0);
        if byte < 0x80 {
            return Ok(value);
        }
    }
    Err(corrupt("varint too long"))
}

fn u32_at(bytes: &[u8], position: usize) -> Result<u32> {
    let slice = bytes.get(position..position + 4).ok_or_else(|| corrupt("truncated"))?;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}

fn decode_block(block: &[u8], first: u32) -> Result<Vec<Run>> {
    let mut position = 0;
    let count = varint(block, &mut position)? as usize;
    ensure(count <= block.len(), "bad run count")?;
    let gaps =
        (0..count).map(|_| varint(block, &mut position)).collect::<Result<Vec<_>>>()?;
    let lengths =
        (0..count).map(|_| varint(block, &mut position)).collect::<Result<Vec<_>>>()?;
    let mut templates =
        block.get(position..).unwrap_or_default().split(|&byte| byte == 0);

    let mut next = first;
    let mut runs = Vec::with_capacity(count);
    for (gap, length) in gaps.into_iter().zip(lengths) {
        let start = next.checked_add(gap).ok_or_else(|| corrupt("bad gap"))?;
        let end = start.checked_add(length).ok_or_else(|| corrupt("bad length"))?;
        next = end.wrapping_add(1);
        let template = templates.next().ok_or_else(|| corrupt("missing template"))?;
        runs.push(Run { start, end, template: template.to_vec() });
    }
    Ok(runs)
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Database> {
        Database::from_bytes(std::fs::read(path)?).map_err(std::io::Error::other)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Database> {
        ensure(bytes.starts_with(MAGIC), "not an rdns database")?;
        let block_count = u32_at(&bytes, 4)? as usize;
        let index_end = block_count
            .checked_mul(8)
            .and_then(|size| size.checked_add(8))
            .filter(|&end| end <= bytes.len())
            .ok_or_else(|| corrupt("truncated index"))?;
        let (entries, _) = bytes[8..index_end].as_chunks::<8>();
        let field = |entry: &[u8; 8], at: usize| u32_at(entry, at);
        let firsts =
            entries.iter().map(|entry| field(entry, 0)).collect::<Result<_>>()?;
        let mut offsets = vec![index_end];
        for entry in entries {
            offsets.push(index_end + field(entry, 4)? as usize);
        }
        ensure(offsets.is_sorted(), "unordered blocks")?;
        ensure(offsets.last() <= Some(&bytes.len()), "truncated blocks")?;
        Ok(Database { bytes, firsts, offsets })
    }

    pub fn block_count(&self) -> usize {
        self.firsts.len()
    }

    pub fn block(&self, index: usize) -> Result<Vec<Run>> {
        let data = &self.bytes[self.offsets[index]..self.offsets[index + 1]];
        let [literal_context, literal_position, position] = LZMA_SETTINGS;
        let decoder = LzmaReader::new(
            data,
            u64::MAX,
            literal_context,
            literal_position,
            position,
            WINDOW,
            None,
        )
        .map_err(corrupt)?;
        let mut raw = Vec::with_capacity(data.len() * 8);
        decoder.take(WINDOW.into()).read_to_end(&mut raw).map_err(corrupt)?;
        decode_block(&raw, self.firsts[index])
    }

    pub fn lookup(&self, address: Ipv4Addr) -> Result<Vec<String>> {
        let ip = u32::from(address);
        let found = self.firsts.partition_point(|&first| first <= ip).checked_sub(1);
        let Some(index) = found else {
            return Ok(Vec::new());
        };
        let runs = self.block(index)?;
        let run = runs.into_iter().find(|run| run.start <= ip && ip <= run.end);
        Ok(run.map(|run| names(&run.template, ip)).unwrap_or_default())
    }
}
