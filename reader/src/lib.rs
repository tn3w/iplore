use std::collections::HashMap;
use std::io::{Error, Result};
use std::net::IpAddr;
use std::sync::OnceLock;

use liblzma::stream::{Action, Filters, LzmaOptions, Status, Stream};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

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

#[derive(Deserialize)]
struct Section {
    encoding: String,
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
    cache: Vec<Vec<OnceLock<Block>>>,
    plans: [Plan; 2],
}

fn decompress(data: &[u8], settings: [u32; 3], dictionary: u32) -> Vec<u8> {
    let mut options = LzmaOptions::new_preset(6).expect("preset");
    options.dict_size(dictionary).literal_context_bits(settings[0]);
    options.literal_position_bits(settings[1]).position_bits(settings[2]);
    let mut stream =
        Stream::new_raw_decoder(Filters::new().lzma1(&options)).expect("lzma");
    let (mut output, mut input) = (Vec::with_capacity(data.len() * 4), data);
    loop {
        output.reserve(64 * 1024);
        let before = stream.total_in();
        let status = stream.process_vec(input, &mut output, Action::Run).expect("lzma");
        input = &input[(stream.total_in() - before) as usize..];
        if status == Status::StreamEnd {
            return output;
        }
    }
}

fn varint(bytes: &[u8], position: &mut usize) -> u128 {
    let (mut value, mut shift) = (0u128, 0);
    loop {
        let byte = bytes[*position];
        *position += 1;
        value |= u128::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return value;
        }
        shift += 7;
    }
}

fn unzigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

fn decode_ints(raw: &[u8]) -> Block {
    let (width, delta) = ((raw[0] & 0x7f) as usize, raw[0] & 0x80 != 0);
    let mut previous = 0u64;
    let values = raw[1..].chunks(width).map(|chunk| {
        let mut bytes = [0u8; 8];
        bytes[..width].copy_from_slice(chunk);
        let value = u64::from_le_bytes(bytes);
        previous =
            if delta { previous.wrapping_add(unzigzag(value) as u64) } else { value };
        previous as u32
    });
    Block::Ints(values.collect())
}

fn decode_keys(raw: &[u8], first: u128, family: u32) -> Block {
    let (mut keys, mut position, mut previous) = (Vec::new(), 0, first);
    while position < raw.len() {
        let gap = varint(raw, &mut position);
        if family == 6 {
            let low = varint(raw, &mut position);
            let low = if gap == 0 { (previous as u64 as u128) + low } else { low };
            previous = (((previous >> 64) + gap) << 64) | low;
        } else {
            previous += gap;
        }
        keys.push(previous);
    }
    match family {
        4 => Block::Keys4(keys.into_iter().map(|key| key as u32).collect()),
        _ => Block::Keys6(keys),
    }
}

fn decode_strings(raw: &[u8]) -> Block {
    let (mut strings, mut position, mut previous) = (Vec::new(), 0, Vec::new());
    while position < raw.len() {
        let shared = varint(raw, &mut position) as usize;
        let length = varint(raw, &mut position) as usize;
        previous.truncate(shared);
        previous.extend_from_slice(&raw[position..position + length]);
        position += length;
        strings.push(String::from_utf8_lossy(&previous).into());
    }
    Block::Strings(strings)
}

fn last_at_most<T: Copy + Into<u128>>(
    keys: &[T],
    address: u128,
) -> Option<(usize, u128)> {
    let index = keys.partition_point(|&key| key.into() <= address).checked_sub(1)?;
    Some((index, keys[index].into()))
}

impl Header {
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
        let vocabulary = |name: &String| self.vocabularies[name].clone();
        let decode = match (&spec.link, &spec.vocab, &spec.flags, spec.kind.as_deref()) {
            (Some(_), ..) => Decode::Link,
            (_, Some(name), ..) => Decode::Vocab(vocabulary(name)),
            (_, _, Some(name), _) => Decode::Flags(vocabulary(name)),
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

impl Reader {
    pub fn open(path: &str) -> Result<Reader> {
        Reader::from_bytes(std::fs::read(path)?)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Reader> {
        if bytes.len() < 12 || &bytes[..8] != b"IPLORE\0\x01" {
            return Err(Error::other("not an iplore v1 file"));
        }
        let length =
            u32::from_le_bytes(bytes[8..12].try_into().expect("length")) as usize;
        let raw = decompress(&bytes[12..12 + length], [3, 0, 0], 1 << 20);
        let about: Value = serde_json::from_slice(&raw).map_err(Error::other)?;
        let header = Header::deserialize(&about).map_err(Error::other)?;
        let firsts = header.sections.iter().map(|section| {
            section.firsts.iter().map(|first| first.parse().unwrap_or(0)).collect()
        });
        let cache = header
            .sections
            .iter()
            .map(|section| (1..section.offsets.len()).map(|_| OnceLock::new()).collect());
        Ok(Reader {
            bytes,
            data_start: 12 + length,
            firsts: firsts.collect(),
            cache: cache.collect(),
            plans: [4, 6].map(|family| header.plan(family)),
            header,
            about,
        })
    }

    pub fn about(&self) -> &Value {
        &self.about
    }

    fn block(&self, section: usize, block: usize) -> &Block {
        self.cache[section][block].get_or_init(|| {
            let spec = &self.header.sections[section];
            let start = self.data_start + spec.offsets[block];
            let end = self.data_start + spec.offsets[block + 1];
            let raw =
                decompress(&self.bytes[start..end], spec.lzma, self.header.dictionary);
            let first = self.firsts[section].get(block).copied().unwrap_or(0);
            match spec.encoding.as_str() {
                "ints" => decode_ints(&raw),
                "keys" => decode_keys(&raw, first, spec.family.unwrap_or(4)),
                _ => decode_strings(&raw),
            }
        })
    }

    fn int(&self, section: usize, row: usize) -> u64 {
        let size = self.header.sections[section].block;
        let Block::Ints(values) = self.block(section, row / size) else { return 0 };
        u64::from(values[row % size])
    }

    fn text(&self, index: usize) -> String {
        let section = self.header.sections.len() - 1;
        let size = self.header.sections[section].block;
        let Block::Strings(strings) = self.block(section, index / size) else {
            return String::new();
        };
        strings[index % size].to_string()
    }

    fn find(&self, section: Option<usize>, address: u128, exact: bool) -> Option<usize> {
        let section = section?;
        let firsts = &self.firsts[section];
        let block = firsts.partition_point(|&first| first <= address).checked_sub(1)?;
        let (index, found) = match self.block(section, block) {
            Block::Keys4(keys) => last_at_most(keys, address),
            Block::Keys6(keys) => last_at_most(keys, address),
            _ => None,
        }?;
        let row = block * self.header.sections[section].block + index;
        (!exact || found == address).then_some(row)
    }

    fn decode(&self, decode: &Decode, value: u64) -> Option<Value> {
        Some(match decode {
            Decode::Link => return None,
            Decode::Text => json!(self.text(value as usize)),
            Decode::Vocab(members) => json!(members.get(value as usize)?),
            Decode::Flags(names) => {
                let set =
                    names.iter().enumerate().filter(|(bit, _)| value >> bit & 1 == 1);
                json!(set.map(|(_, name)| name).collect::<Vec<_>>())
            }
            Decode::Bool => json!(value == 1),
            Decode::Number(scale, signed) => {
                let number = if *signed { unzigzag(value) } else { value as i64 };
                scale.map_or(json!(number), |scale| json!(number as f64 / scale as f64))
            }
        })
    }

    pub fn lookup_json(&self, text: &str) -> Option<Value> {
        let (plan, address) = match parse_address(text)? {
            IpAddr::V4(v4) => (&self.plans[0], u128::from(u32::from(v4))),
            IpAddr::V6(v6) => (&self.plans[1], u128::from(v6)),
        };
        let spine = self.find(plan.spine, address, false);
        let host = self.find(plan.hosts, address, true);
        let read = |node: &Node, rows: &[Option<usize>]| {
            let (row, host) =
                node.parent.map_or((spine, host), |parent| (rows[parent], None));
            let value = match (node.host_section, host) {
                (Some(section), Some(host)) => self.int(section, host),
                _ => self.int(node.section, row?),
            };
            value.checked_sub(1)
        };
        let mut rows = Vec::with_capacity(plan.links.len());
        for node in &plan.links {
            rows.push(read(node, &rows).map(|value| value as usize));
        }
        let mut tree = Map::new();
        for (name, node) in &plan.leaves {
            let value =
                read(node, &rows).and_then(|value| self.decode(&node.decode, value));
            if let Some(value) = value {
                insert(&mut tree, name, value);
            }
        }
        Some(Value::Object(tree))
    }

    pub fn lookup(&self, text: &str) -> Option<Answer> {
        Answer::deserialize(self.lookup_json(text)?).ok()
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

pub fn parse_address(text: &str) -> Option<IpAddr> {
    let text =
        text.trim().trim_start_matches('[').split(']').next()?.split('%').next()?;
    match text.parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => Some(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)),
        v4 => Some(v4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_address_spellings() {
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        for text in ["1.2.3.4", " ::ffff:1.2.3.4 ", "[::ffff:1.2.3.4]:80"] {
            assert_eq!(parse_address(text), Some(v4));
        }
        assert_eq!(parse_address("fe80::1%eth0"), "fe80::1".parse().ok());
        assert_eq!(parse_address("not an address"), None);
    }

    #[test]
    fn decodes_blocks() {
        let Block::Ints(values) = decode_ints(&[0x81, 2, 2, 1]) else { panic!() };
        assert_eq!(values, vec![1, 2, 1]);
        let Block::Keys4(keys) = decode_keys(&[0, 5, 0x80, 1], 10, 4) else { panic!() };
        assert_eq!(keys, vec![10, 15, 143]);
        let Block::Strings(strings) = decode_strings(&[0, 2, b'a', b'b', 1, 1, b'c'])
        else {
            panic!()
        };
        assert_eq!(strings, vec!["ab".into(), "ac".into()]);
    }
}
