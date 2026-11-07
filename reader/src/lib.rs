use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use std::path::Path;
use std::sync::OnceLock;

use lzma_rust2::LzmaReader;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

const MAX_DECOMPRESSED: usize = 1 << 24;
const MAX_DICTIONARY: u32 = 1 << 26;
const MAX_BLOCK_ROWS: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    InvalidAddress,
    Corrupt(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidAddress => write!(formatter, "invalid address"),
            Error::Corrupt(reason) => write!(formatter, "corrupt database: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

fn corrupt(reason: impl ToString) -> Error {
    Error::Corrupt(reason.to_string())
}

fn ensure(condition: bool, reason: &str) -> Result<()> {
    condition.then_some(()).ok_or_else(|| corrupt(reason))
}

macro_rules! group {
    ($name:ident { $($field:ident: $kind:ty),* $(,)? }) => {
        #[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
        #[serde(default)]
        pub struct $name { $(pub $field: Option<$kind>),* }
    };
}

group!(Answer { place: Place, network: Network, abuse: Abuse });

group!(Place {
    lat: f64,
    lon: f64,
    accuracy: u64,
    confidence: u64,
    city: City,
    region: Region,
    country: Country,
});

group!(City {
    name: String,
    geonames_id: u64,
    population: u64,
    district: String,
    postal: String,
    metro: String,
    timezone: String,
});

group!(Region { name: String, iso: String, geonames_id: u64 });

group!(Country {
    code: String,
    name: String,
    continent: String,
    currency: String,
    calling_code: String,
    languages: String,
    eu: bool,
});

group!(Network {
    asn: u64,
    handle: String,
    prefix: u64,
    rir: String,
    country: String,
    year: u64,
    rpki: String,
    users: u64,
    mobile_code: String,
    risk: f64,
    operator: Operator,
});

group!(Operator {
    company: String,
    category: String,
    website: String,
    address: String,
    country: String,
    abuse_email: String,
    since: u64,
    tier: u64,
    cone: u64,
});

group!(Abuse {
    risk: f64,
    threat: String,
    reports: u64,
    last_seen_days: u64,
    service: String,
    evidence: String,
    provider: String,
    user_type: String,
    flags: Vec<String>,
});

#[derive(Deserialize)]
struct Column {
    kind: Option<String>,
    scale: Option<u64>,
    vocab: Option<String>,
    flags: Option<String>,
    link: Option<String>,
    section: usize,
}

#[derive(Deserialize)]
struct Table {
    keys: Option<usize>,
    columns: HashMap<String, Column>,
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Encoding {
    Ints,
    Keys,
    Strings,
}

#[derive(Deserialize)]
struct Section {
    encoding: Encoding,
    block: usize,
    lzma: [u32; 3],
    offsets: Vec<usize>,
    #[serde(default)]
    firsts: Vec<String>,
    family: Option<u32>,
}

#[derive(Deserialize)]
struct Field {
    name: String,
    path: Vec<String>,
}

#[derive(Deserialize)]
struct Header {
    dictionary: u32,
    fields: Vec<Field>,
    vocabularies: HashMap<String, Vec<String>>,
    tables: HashMap<String, Table>,
    sections: Vec<Section>,
}

enum Block {
    Ints(Vec<u32>),
    Keys4(Vec<u32>),
    Keys6(Vec<u128>),
    Strings(Vec<Box<str>>),
}

enum Decode {
    Link,
    Number(Option<u64>, bool),
    Text,
    Vocab(Vec<String>),
    Flags(Vec<String>),
    Bool,
}

struct Node {
    parent: Option<usize>,
    section: usize,
    host_section: Option<usize>,
    decode: Decode,
}

struct Plan {
    spine: Option<usize>,
    hosts: Option<usize>,
    links: Vec<Node>,
    leaves: Vec<(String, Node)>,
}

pub struct Reader {
    bytes: Vec<u8>,
    data_start: usize,
    header: Header,
    about: Value,
    firsts: Vec<Vec<u128>>,
    cache: Vec<Vec<OnceLock<Result<Block>>>>,
    plans: [Plan; 2],
}

fn decompress(
    data: &[u8],
    settings: [u32; 3],
    dictionary: u32,
    limit: usize,
) -> Result<Vec<u8>> {
    let [literal_context, literal_position, position] = settings;
    ensure(literal_context <= 8 && literal_position <= 4, "bad lzma settings")?;
    ensure(position <= 4 && dictionary <= MAX_DICTIONARY, "bad lzma settings")?;
    let decoder = LzmaReader::new(
        data,
        u64::MAX,
        literal_context,
        literal_position,
        position,
        dictionary,
        None,
    )
    .map_err(corrupt)?;
    let mut output = Vec::with_capacity(data.len().saturating_mul(4).min(limit));
    decoder.take(limit as u64 + 1).read_to_end(&mut output).map_err(corrupt)?;
    ensure(output.len() <= limit, "decompressed data too large")?;
    Ok(output)
}

fn varint(bytes: &[u8], position: &mut usize) -> Result<u128> {
    let (mut value, mut shift) = (0u128, 0);
    loop {
        let byte = *bytes.get(*position).ok_or_else(|| corrupt("truncated varint"))?;
        *position += 1;
        ensure(shift <= 126, "varint too long")?;
        let part = u128::from(byte & 0x7f);
        ensure((part << shift) >> shift == part, "varint overflow")?;
        value |= part << shift;
        if byte < 0x80 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn unzigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

fn decode_ints(raw: &[u8], limit: usize) -> Result<Block> {
    let (&format, body) = raw.split_first().ok_or_else(|| corrupt("empty block"))?;
    let (width, delta) = (usize::from(format & 0x7f), format & 0x80 != 0);
    ensure((1..=8).contains(&width), "bad integer width")?;
    ensure(body.len() % width == 0, "partial integer")?;
    ensure(body.len() / width <= limit, "too many rows")?;
    let mut previous = 0u64;
    let values = body.chunks_exact(width).map(|chunk| {
        let mut bytes = [0u8; 8];
        bytes[..width].copy_from_slice(chunk);
        let value = u64::from_le_bytes(bytes);
        previous =
            if delta { previous.wrapping_add(unzigzag(value) as u64) } else { value };
        u32::try_from(previous).map_err(|_| corrupt("integer out of range"))
    });
    Ok(Block::Ints(values.collect::<Result<_>>()?))
}

fn next_key6(previous: u128, gap: u128, low: u128) -> Result<u128> {
    let (high, low) = match gap {
        0 => (Some(previous >> 64), (previous & u128::from(u64::MAX)).checked_add(low)),
        _ => ((previous >> 64).checked_add(gap), Some(low)),
    };
    let limit = u128::from(u64::MAX);
    match (high, low) {
        (Some(high), Some(low)) if high <= limit && low <= limit => {
            Ok((high << 64) | low)
        }
        _ => Err(corrupt("key overflow")),
    }
}

fn decode_keys(raw: &[u8], first: u128, family: u32, limit: usize) -> Result<Block> {
    let (mut keys, mut position, mut previous) = (Vec::new(), 0, first);
    while position < raw.len() {
        ensure(keys.len() < limit, "too many rows")?;
        let gap = varint(raw, &mut position)?;
        let key = if family == 6 {
            next_key6(previous, gap, varint(raw, &mut position)?)?
        } else {
            previous.checked_add(gap).ok_or_else(|| corrupt("key overflow"))?
        };
        ensure(keys.last().is_none_or(|&last| key > last), "keys not increasing")?;
        keys.push(key);
        previous = key;
    }
    if family == 6 {
        return Ok(Block::Keys6(keys));
    }
    let narrow = keys.into_iter().map(u32::try_from);
    Ok(Block::Keys4(narrow.collect::<std::result::Result<_, _>>().map_err(corrupt)?))
}

fn decode_strings(raw: &[u8], limit: usize) -> Result<Block> {
    let (mut strings, mut position, mut previous) = (Vec::new(), 0, Vec::new());
    let mut total = 0usize;
    while position < raw.len() {
        ensure(strings.len() < limit, "too many rows")?;
        let shared = usize::try_from(varint(raw, &mut position)?).map_err(corrupt)?;
        let length = usize::try_from(varint(raw, &mut position)?).map_err(corrupt)?;
        ensure(shared <= previous.len(), "shared prefix too long")?;
        let end = position.checked_add(length);
        let suffix = end.and_then(|end| raw.get(position..end));
        previous.truncate(shared);
        previous.extend_from_slice(suffix.ok_or_else(|| corrupt("truncated string"))?);
        position += length;
        total = total.saturating_add(previous.len());
        ensure(total <= MAX_DECOMPRESSED, "strings too large")?;
        strings.push(String::from_utf8_lossy(&previous).into());
    }
    Ok(Block::Strings(strings))
}

fn last_at_most<T: Copy + Into<u128>>(
    keys: &[T],
    address: u128,
) -> Option<(usize, u128)> {
    let index = keys.partition_point(|&key| key.into() <= address).checked_sub(1)?;
    Some((index, keys.get(index).copied()?.into()))
}

impl Section {
    fn span(&self, block: usize) -> Option<Range<usize>> {
        let start = *self.offsets.get(block)?;
        Some(start..*self.offsets.get(block.checked_add(1)?)?)
    }

    fn validate(&self, data_length: usize) -> Result<()> {
        ensure((1..=MAX_BLOCK_ROWS).contains(&self.block), "bad block size")?;
        let [literal_context, literal_position, position] = self.lzma;
        ensure(literal_context <= 8 && literal_position <= 4, "bad lzma settings")?;
        ensure(position <= 4, "bad lzma settings")?;
        ensure(
            self.offsets.last().is_some_and(|&end| end <= data_length),
            "bad offsets",
        )?;
        ensure(self.offsets.is_sorted(), "unsorted offsets")?;
        if self.encoding != Encoding::Keys {
            return Ok(());
        }
        ensure(matches!(self.family, Some(4 | 6)), "bad key family")?;
        ensure(self.firsts.len() + 1 == self.offsets.len(), "bad first keys")
    }

    fn parse_firsts(&self) -> Result<Vec<u128>> {
        let firsts: Vec<u128> = self
            .firsts
            .iter()
            .map(|first| first.parse())
            .collect::<std::result::Result<_, _>>()
            .map_err(corrupt)?;
        ensure(firsts.is_sorted(), "unsorted first keys")?;
        let narrow = self.family != Some(6);
        ensure(
            firsts.iter().all(|&first| !narrow || u32::try_from(first).is_ok()),
            "bad first keys",
        )?;
        Ok(firsts)
    }
}

impl Header {
    fn validate(&self, data_length: usize) -> Result<()> {
        ensure(self.dictionary <= MAX_DICTIONARY, "dictionary too large")?;
        let strings = self.sections.last().map(|section| &section.encoding);
        ensure(strings == Some(&Encoding::Strings), "last section is not strings")?;
        for section in &self.sections {
            section.validate(data_length)?;
        }
        self.tables.values().try_for_each(|table| self.validate_table(table))
    }

    fn validate_table(&self, table: &Table) -> Result<()> {
        let encoding =
            |section: usize| self.sections.get(section).map(|spec| &spec.encoding);
        if let Some(keys) = table.keys {
            ensure(encoding(keys) == Some(&Encoding::Keys), "bad keys section")?;
        }
        for column in table.columns.values() {
            ensure(encoding(column.section) == Some(&Encoding::Ints), "bad column")?;
            ensure(column.scale != Some(0), "zero scale")?;
            let names = column.vocab.iter().chain(&column.flags);
            ensure(
                names.clone().all(|name| self.vocabularies.contains_key(name)),
                "bad vocabulary",
            )?;
        }
        Ok(())
    }

    fn plan(&self, family: u32) -> Plan {
        let keys = |name: &str| self.tables.get(&format!("{name}{family}"))?.keys;
        let (spine, hosts) = (keys("spine"), keys("hosts"));
        let mut plan = Plan { spine, hosts, links: Vec::new(), leaves: Vec::new() };
        let mut nodes: HashMap<&[String], usize> = HashMap::new();
        'fields: for field in &self.fields {
            let Some((last, links)) = field.path.split_last() else { continue };
            let mut parent = None;
            for depth in 1..=links.len() {
                if let Some(&node) = nodes.get(&links[..depth]) {
                    parent = Some(node);
                    continue;
                }
                let Some(node) = self.node(&links[depth - 1], family, parent) else {
                    continue 'fields;
                };
                nodes.insert(&links[..depth], plan.links.len());
                parent = Some(plan.links.len());
                plan.links.push(node);
            }
            if let Some(node) = self.node(last, family, parent) {
                plan.leaves.push((field.name.clone(), node));
            }
        }
        plan
    }

    fn node(&self, step: &str, family: u32, parent: Option<usize>) -> Option<Node> {
        let family_table = |name: &str| self.tables.get(&format!("{name}{family}"));
        let (table, column) = step.split_once('.')?;
        let spine = table == "spine";
        let source = if spine { family_table("spine") } else { self.tables.get(table) };
        let spec = source?.columns.get(column)?;
        let vocabulary = |name: &String| self.vocabularies.get(name).cloned();
        let decode = match (&spec.link, &spec.vocab, &spec.flags, spec.kind.as_deref()) {
            (Some(_), ..) => Decode::Link,
            (_, Some(name), ..) => Decode::Vocab(vocabulary(name)?),
            (_, _, Some(name), _) => Decode::Flags(vocabulary(name)?),
            (.., Some("string")) => Decode::Text,
            (.., Some("bool")) => Decode::Bool,
            (.., kind) => Decode::Number(spec.scale, kind == Some("signed")),
        };
        let hosts = family_table("hosts").filter(|_| spine);
        let host_section =
            hosts.and_then(|hosts| Some(hosts.columns.get(column)?.section));
        Some(Node { parent, section: spec.section, host_section, decode })
    }
}

fn row(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

impl Reader {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Reader> {
        let invalid = |error| std::io::Error::new(std::io::ErrorKind::InvalidData, error);
        Reader::from_bytes(std::fs::read(path)?).map_err(invalid)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Reader> {
        ensure(bytes.starts_with(b"IPLORE\0\x01"), "not an iplore v1 file")?;
        let length = bytes.get(8..12).and_then(|field| <[u8; 4]>::try_from(field).ok());
        let length =
            length.map(u32::from_le_bytes).ok_or_else(|| corrupt("truncated"))?;
        let data_start =
            usize::try_from(length).ok().and_then(|size| size.checked_add(12));
        let data_start = data_start.ok_or_else(|| corrupt("header exceeds file"))?;
        let compressed = bytes.get(12..data_start);
        let compressed = compressed.ok_or_else(|| corrupt("header exceeds file"))?;
        let raw = decompress(compressed, [3, 0, 0], 1 << 20, MAX_DECOMPRESSED)?;
        let about = serde_json::from_slice(&raw).map_err(corrupt)?;
        Reader::new(bytes, data_start, about)
    }

    fn new(bytes: Vec<u8>, data_start: usize, mut about: Value) -> Result<Reader> {
        let header = Header::deserialize(&about).map_err(corrupt)?;
        header.validate(bytes.len().saturating_sub(data_start))?;
        strip_offsets(&mut about);
        let firsts = header.sections.iter().map(Section::parse_firsts);
        let cache = header
            .sections
            .iter()
            .map(|section| section.offsets.iter().skip(1).map(|_| OnceLock::new()));
        Ok(Reader {
            bytes,
            data_start,
            firsts: firsts.collect::<Result<_>>()?,
            cache: cache.map(Iterator::collect).collect(),
            plans: [4, 6].map(|family| header.plan(family)),
            header,
            about,
        })
    }

    pub fn about(&self) -> &Value {
        &self.about
    }

    fn block(&self, section: usize, block: usize) -> Result<&Block> {
        let cell = self.cache.get(section).and_then(|cells| cells.get(block));
        let cell = cell.ok_or_else(|| corrupt("block out of range"))?;
        cell.get_or_init(|| self.load(section, block)).as_ref().map_err(Error::clone)
    }

    fn load(&self, section: usize, block: usize) -> Result<Block> {
        let spec = self.header.sections.get(section);
        let spec = spec.ok_or_else(|| corrupt("section out of range"))?;
        let span = spec.span(block).ok_or_else(|| corrupt("block out of range"))?;
        let start = self.data_start.saturating_add(span.start);
        let end = self.data_start.saturating_add(span.end);
        let compressed = self.bytes.get(start..end);
        let compressed = compressed.ok_or_else(|| corrupt("block outside file"))?;
        let raw =
            decompress(compressed, spec.lzma, self.header.dictionary, MAX_DECOMPRESSED)?;
        let first = self.firsts.get(section).and_then(|firsts| firsts.get(block));
        match spec.encoding {
            Encoding::Ints => decode_ints(&raw, spec.block),
            Encoding::Strings => decode_strings(&raw, spec.block),
            Encoding::Keys => {
                let first = first.copied().unwrap_or_default();
                decode_keys(&raw, first, spec.family.unwrap_or(4), spec.block)
            }
        }
    }

    fn locate(&self, section: usize, row: usize) -> Result<(usize, usize)> {
        let size = self.header.sections.get(section).map(|spec| spec.block);
        let size = size.filter(|&size| size > 0).ok_or_else(|| corrupt("bad section"))?;
        Ok((row / size, row % size))
    }

    fn int(&self, section: usize, row: usize) -> Result<u32> {
        let (block, offset) = self.locate(section, row)?;
        let Block::Ints(values) = self.block(section, block)? else {
            return Err(corrupt("not an integer section"));
        };
        values.get(offset).copied().ok_or_else(|| corrupt("row out of range"))
    }

    fn text(&self, index: usize) -> Result<String> {
        let section = self.header.sections.len().saturating_sub(1);
        let (block, offset) = self.locate(section, index)?;
        let Block::Strings(strings) = self.block(section, block)? else {
            return Err(corrupt("not a string section"));
        };
        let text = strings.get(offset).ok_or_else(|| corrupt("string out of range"))?;
        Ok(text.to_string())
    }

    fn find(
        &self,
        section: Option<usize>,
        address: u128,
        exact: bool,
    ) -> Result<Option<usize>> {
        let Some(section) = section else { return Ok(None) };
        let Some(firsts) = self.firsts.get(section) else { return Ok(None) };
        let covering = firsts.partition_point(|&first| first <= address);
        let Some(block) = covering.checked_sub(1) else { return Ok(None) };
        let found = match self.block(section, block)? {
            Block::Keys4(keys) => last_at_most(keys, address),
            Block::Keys6(keys) => last_at_most(keys, address),
            _ => None,
        };
        let Some((index, key)) = found else { return Ok(None) };
        let size = self.header.sections.get(section).map_or(0, |spec| spec.block);
        let found = block.saturating_mul(size).saturating_add(index);
        Ok((!exact || key == address).then_some(found))
    }

    fn decode(&self, decode: &Decode, value: u32) -> Result<Option<Value>> {
        Ok(match decode {
            Decode::Link => None,
            Decode::Text => Some(json!(self.text(row(value))?)),
            Decode::Vocab(members) => members.get(row(value)).map(|member| json!(member)),
            Decode::Flags(names) => {
                let set = names.iter().take(32).enumerate();
                let set = set.filter(|(bit, _)| value >> bit & 1 == 1);
                Some(json!(set.map(|(_, name)| name).collect::<Vec<_>>()))
            }
            Decode::Bool => Some(json!(value == 1)),
            Decode::Number(scale, signed) => {
                let number =
                    if *signed { unzigzag(u64::from(value)) } else { i64::from(value) };
                Some(
                    scale.map_or(json!(number), |scale| {
                        json!(number as f64 / scale as f64)
                    }),
                )
            }
        })
    }

    pub fn lookup_json(&self, text: &str) -> Result<Value> {
        let (plan, address) = match parse_address(text).ok_or(Error::InvalidAddress)? {
            IpAddr::V4(v4) => (&self.plans[0], u128::from(u32::from(v4))),
            IpAddr::V6(v6) => (&self.plans[1], u128::from(v6)),
        };
        let spine = self.find(plan.spine, address, false)?;
        let host = self.find(plan.hosts, address, true)?;
        let read = |node: &Node, rows: &[Option<usize>]| -> Result<Option<u32>> {
            let (row, host) = match node.parent {
                Some(parent) => (rows.get(parent).copied().flatten(), None),
                None => (spine, host),
            };
            let value = match (node.host_section, host) {
                (Some(section), Some(host)) => self.int(section, host)?,
                _ => {
                    let Some(row) = row else { return Ok(None) };
                    self.int(node.section, row)?
                }
            };
            Ok(value.checked_sub(1))
        };
        let mut rows = Vec::with_capacity(plan.links.len());
        for node in &plan.links {
            rows.push(read(node, &rows)?.map(row));
        }
        let mut tree = Map::new();
        for (name, node) in &plan.leaves {
            let Some(value) = read(node, &rows)? else { continue };
            if let Some(value) = self.decode(&node.decode, value)? {
                insert(&mut tree, name, value);
            }
        }
        Ok(Value::Object(tree))
    }

    pub fn lookup(&self, text: &str) -> Result<Answer> {
        Answer::deserialize(self.lookup_json(text)?).map_err(corrupt)
    }
}

fn strip_offsets(about: &mut Value) {
    let sections = about.get_mut("sections").and_then(Value::as_array_mut);
    for section in sections.into_iter().flatten() {
        if let Some(section) = section.as_object_mut() {
            section.retain(|key, _| key != "offsets" && key != "firsts");
        }
    }
}

fn insert(tree: &mut Map<String, Value>, name: &str, value: Value) {
    let Some((head, rest)) = name.split_once('.') else {
        tree.insert(name.to_string(), value);
        return;
    };
    let child = tree.entry(head).or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(child) = child {
        insert(child, rest, value);
    }
}

fn valid_port(port: &str) -> bool {
    port.len() <= 5
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && !port.is_empty()
        && port.parse::<u16>().is_ok()
}

fn valid_zone(zone: &str) -> bool {
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || b"._-".contains(&byte);
    !zone.is_empty() && zone.bytes().all(allowed)
}

fn ipv6(text: &str) -> Option<Ipv6Addr> {
    let (address, zone) =
        text.split_once('%').map_or((text, None), |(a, z)| (a, Some(z)));
    if zone.is_some_and(|zone| !valid_zone(zone)) {
        return None;
    }
    address.parse().ok()
}

fn bracketed(rest: &str) -> Option<IpAddr> {
    let (inside, after) = rest.split_once(']')?;
    let valid = after.is_empty() || after.strip_prefix(':').is_some_and(valid_port);
    valid.then_some(())?;
    ipv6(inside).map(IpAddr::V6)
}

fn bare(text: &str) -> Option<IpAddr> {
    if let Some(v6) = ipv6(text) {
        return Some(IpAddr::V6(v6));
    }
    let (host, port) = text.split_once(':').map_or((text, None), |(h, p)| (h, Some(p)));
    if port.is_some_and(|port| !valid_port(port)) {
        return None;
    }
    host.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

pub fn parse_address(text: &str) -> Option<IpAddr> {
    let address = match text.strip_prefix('[') {
        Some(rest) => bracketed(rest)?,
        None => bare(text)?,
    };
    match address {
        IpAddr::V6(v6) => Some(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)),
        v4 => Some(v4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(result: Result<Block>) -> String {
        match result {
            Err(Error::Corrupt(reason)) => reason,
            _ => panic!("expected corruption error"),
        }
    }

    fn encode(mut value: u128) -> Vec<u8> {
        let mut output = Vec::new();
        while value >= 0x80 {
            output.push((value as u8) | 0x80);
            value >>= 7;
        }
        output.push(value as u8);
        output
    }

    #[test]
    fn varint_rejects_truncation_and_overflow() {
        assert_eq!(varint(&[0x80, 1], &mut 0), Ok(128));
        assert!(varint(&[], &mut 0).is_err());
        assert!(varint(&[0x80], &mut 0).is_err());
        assert!(varint(&[0x80; 40], &mut 0).is_err());
        let mut maximal = vec![0xff; 18];
        maximal.push(0x03);
        assert_eq!(varint(&maximal, &mut 0), Ok(u128::MAX));
        maximal[18] = 0x04;
        assert!(varint(&maximal, &mut 0).is_err());
    }

    #[test]
    fn ints_reject_bad_widths_and_partial_chunks() {
        let Ok(Block::Ints(values)) = decode_ints(&[0x81, 2, 2, 1], 8) else { panic!() };
        assert_eq!(values, vec![1, 2, 1]);
        assert_eq!(message(decode_ints(&[], 8)), "empty block");
        assert_eq!(message(decode_ints(&[0, 1], 8)), "bad integer width");
        assert_eq!(message(decode_ints(&[9; 20], 8)), "bad integer width");
        assert_eq!(message(decode_ints(&[2, 1, 0, 1], 8)), "partial integer");
        assert_eq!(message(decode_ints(&[1, 1, 2, 3], 2)), "too many rows");
        let wide = [8, 0, 0, 0, 0, 1, 0, 0, 0];
        assert_eq!(message(decode_ints(&wide, 8)), "integer out of range");
    }

    #[test]
    fn keys_reject_overflow_and_disorder() {
        let Ok(Block::Keys4(keys)) = decode_keys(&[0, 5, 0x80, 1], 10, 4, 8) else {
            panic!()
        };
        assert_eq!(keys, vec![10, 15, 143]);
        assert_eq!(message(decode_keys(&[0, 0x80], 0, 4, 8)), "truncated varint");
        assert_eq!(message(decode_keys(&[0, 0], 0, 4, 8)), "keys not increasing");
        assert_eq!(message(decode_keys(&[0, 1, 0, 1], 0, 4, 2)), "too many rows");
        let beyond = [0, 0xff, 0xff, 0xff, 0xff, 0x0f, 1];
        assert!(decode_keys(&beyond, 0, 4, 8).is_err());
        let high = [&[0][..], &encode(1 << 70), &[0]].concat();
        assert_eq!(message(decode_keys(&high, 0, 6, 8)), "key overflow");
        let wrap = [&[0, 0xff, 0xff, 0xff, 0xff, 0xff][..], &[0xff; 4], &[1, 0, 1]];
        assert!(decode_keys(&wrap.concat(), 0, 6, 8).is_err());
    }

    #[test]
    fn strings_reject_bad_prefixes_and_blowup() {
        let valid = [0, 2, b'a', b'b', 1, 1, b'c'];
        let Ok(Block::Strings(strings)) = decode_strings(&valid, 8) else { panic!() };
        assert_eq!(strings, vec!["ab".into(), "ac".into()]);
        let shared = [0, 1, b'a', 2, 0];
        assert_eq!(message(decode_strings(&shared, 8)), "shared prefix too long");
        let long = [0, 5, b'a'];
        assert_eq!(message(decode_strings(&long, 8)), "truncated string");
        let growing: Vec<u8> = (0..20_000u128)
            .flat_map(|length| [encode(length), vec![1, b'a']].concat())
            .collect();
        assert_eq!(message(decode_strings(&growing, 20_000)), "strings too large");
    }

    #[test]
    fn decompress_rejects_bad_settings_and_limits() {
        assert!(decompress(&[], [9, 0, 0], 1 << 20, 64).is_err());
        assert!(decompress(&[], [3, 5, 0], 1 << 20, 64).is_err());
        assert!(decompress(&[], [3, 0, 5], 1 << 20, 64).is_err());
        assert!(decompress(&[], [3, 0, 0], u32::MAX, 64).is_err());
        assert!(decompress(&[0; 8], [3, 0, 0], 1 << 20, 64).is_err());
        let Ok(bytes) = std::fs::read("../bindings/data/iplore-country.ipl") else {
            return;
        };
        let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let header = &bytes[12..12 + length];
        assert!(decompress(header, [3, 0, 0], 1 << 20, MAX_DECOMPRESSED).is_ok());
        assert!(decompress(header, [3, 0, 0], 1 << 20, 1000).is_err());
        assert!(decompress(&header[..length / 2], [3, 0, 0], 1 << 20, 1 << 24).is_err());
    }

    fn tiny() -> Reader {
        let about = json!({
            "dictionary": 1 << 20,
            "fields": [{
                "name": "place.country.code",
                "path": ["spine.place", "place.country", "country.code"],
            }],
            "vocabularies": {},
            "tables": {
                "spine4": {"keys": 0, "columns": {
                    "place": {"link": "place", "section": 1}}},
                "place": {"columns": {"country": {"link": "country", "section": 2}}},
                "country": {"columns": {"code": {"kind": "string", "section": 3}}},
            },
            "sections": [
                {"encoding": "keys", "block": 8, "lzma": [0, 0, 0], "family": 4,
                 "offsets": [0, 0], "firsts": ["0"]},
                {"encoding": "ints", "block": 8, "lzma": [0, 0, 0], "offsets": [0, 0]},
                {"encoding": "ints", "block": 8, "lzma": [0, 0, 0], "offsets": [0, 0]},
                {"encoding": "ints", "block": 8, "lzma": [0, 0, 0], "offsets": [0, 0]},
                {"encoding": "strings", "block": 8, "lzma": [0, 0, 0], "offsets": [0, 0]},
            ],
        });
        let reader = Reader::new(Vec::new(), 0, about).unwrap();
        let fill = |section: usize, block: Block| {
            assert!(reader.cache[section][0].set(Ok(block)).is_ok());
        };
        fill(0, Block::Keys4(vec![0]));
        fill(1, Block::Ints(vec![2]));
        fill(2, Block::Ints(vec![0, 3]));
        fill(3, Block::Ints(vec![0, 0, 5]));
        reader
    }

    fn texts(reader: &Reader, strings: &[&str]) {
        let block = strings.iter().map(|text| Box::from(*text)).collect();
        assert!(reader.cache[4][0].set(Ok(Block::Strings(block))).is_ok());
    }

    #[test]
    fn lookup_follows_links() {
        let reader = tiny();
        texts(&reader, &["a", "b", "c", "d", "XX"]);
        let answer = reader.lookup("0.0.0.9").unwrap();
        assert_eq!(answer.place.unwrap().country.unwrap().code.as_deref(), Some("XX"));
    }

    #[test]
    fn lookup_reports_out_of_range_rows_instead_of_panicking() {
        let reader = tiny();
        texts(&reader, &["a", "b"]);
        let result = reader.lookup("0.0.0.9");
        assert_eq!(result, Err(Error::Corrupt("string out of range".into())));
        assert_eq!(reader.lookup("nope"), Err(Error::InvalidAddress));
        assert_eq!(reader.lookup("::1").unwrap(), Answer::default());
    }

    fn broken(pointer: &str, replacement: Value) -> Result<()> {
        let mut about = json!({
            "dictionary": 1 << 20,
            "fields": [],
            "vocabularies": {"names": ["x"]},
            "tables": {"spine4": {"keys": 0, "columns": {
                "name": {"vocab": "names", "section": 1, "scale": 2}}}},
            "sections": [
                {"encoding": "keys", "block": 4, "lzma": [0, 0, 0], "family": 4,
                 "offsets": [0, 3, 5], "firsts": ["0", "9"]},
                {"encoding": "ints", "block": 4, "lzma": [0, 0, 0], "offsets": [0, 5]},
                {"encoding": "strings", "block": 4, "lzma": [0, 0, 0], "offsets": [0, 5]},
            ],
        });
        assert!(Header::deserialize(&about).unwrap().validate(5).is_ok());
        *about.pointer_mut(pointer).unwrap() = replacement;
        Header::deserialize(&about).map_err(corrupt)?.validate(5)
    }

    #[test]
    fn validation_rejects_inconsistent_structure() {
        let column = "/tables/spine4/columns/name";
        let cases = [
            ("/sections/1/block", json!(0)),
            ("/sections/1/block", json!(1u64 << 40)),
            ("/sections/1/offsets", json!([0, 6])),
            ("/sections/1/offsets", json!([4, 1, 5])),
            ("/sections/1/offsets", json!([])),
            ("/sections/0/firsts", json!(["0"])),
            ("/sections/0/family", json!(5)),
            ("/sections/1/lzma", json!([9, 0, 0])),
            ("/sections/1/encoding", json!("other")),
            ("/sections/2/encoding", json!("ints")),
            ("/dictionary", json!(u32::MAX)),
            ("/tables/spine4/keys", json!(1)),
            ("/tables/spine4/keys", json!(7)),
            (&format!("{column}/section"), json!(7)),
            (&format!("{column}/section"), json!(2)),
            (&format!("{column}/scale"), json!(0)),
            (&format!("{column}/vocab"), json!("missing")),
        ];
        for (pointer, replacement) in cases {
            assert!(broken(pointer, replacement.clone()).is_err(), "{pointer}");
        }
    }
}
