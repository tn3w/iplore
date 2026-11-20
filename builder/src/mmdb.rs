use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;

use crate::log;
use crate::spans::Address;
use crate::write::{ColumnSpec, Output};

const POINTER: u8 = 1;
const STRING: u8 = 2;
const DOUBLE: u8 = 3;
const UINT16: u8 = 5;
const UINT32: u8 = 6;
const MAP: u8 = 7;
const UINT64: u8 = 9;
const ARRAY: u8 = 11;
const BOOLEAN: u8 = 14;

const EMPTY: u32 = u32::MAX;
const DATA: u32 = 1 << 31;
const IPV4_SPACE: Address = 1 << 32;
const MAPPED: Address = 0xffff << 32;

fn control(bytes: &mut Vec<u8>, kind: u8, size: usize) {
    let (marker, extra) = match size {
        0..29 => (size as u8, Vec::new()),
        29..285 => (29, vec![(size - 29) as u8]),
        285..65821 => (30, ((size - 285) as u16).to_be_bytes().to_vec()),
        _ => (31, ((size - 65821) as u32).to_be_bytes()[1..].to_vec()),
    };
    if kind < 8 {
        bytes.push(kind << 5 | marker);
    } else {
        bytes.extend([marker, kind - 7]);
    }
    bytes.extend(extra);
}

fn pointer(offset: u32) -> Vec<u8> {
    let tagged = |size: u8, value: u32, length: usize| {
        let bytes = value.to_be_bytes();
        let top = if length == 4 { 0 } else { bytes[3 - length] };
        [&[POINTER << 5 | size << 3 | top], &bytes[4 - length..]].concat()
    };
    match offset {
        0..2048 => tagged(0, offset, 1),
        2048..526_336 => tagged(1, offset - 2048, 2),
        526_336..134_744_064 => tagged(2, offset - 526_336, 3),
        _ => tagged(3, offset, 4),
    }
}

fn unsigned(bytes: &mut Vec<u8>, kind: u8, value: u64) {
    let raw = value.to_be_bytes();
    let significant = &raw[value.leading_zeros() as usize / 8..];
    control(bytes, kind, significant.len());
    bytes.extend(significant);
}

fn inline_text(bytes: &mut Vec<u8>, value: &str) {
    control(bytes, STRING, value.len());
    bytes.extend(value.as_bytes());
}

fn unzigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

type Entry<'a> = (&'a str, &'a str, &'a str, u64);

struct Data<'a> {
    output: &'a Output,
    columns: &'a BTreeMap<String, ColumnSpec>,
    vocabularies: &'a BTreeMap<String, Vec<String>>,
    bytes: Vec<u8>,
    strings: HashMap<&'a str, u32>,
    rows: HashMap<(&'a str, u64), u32>,
    composites: HashMap<(&'a str, Vec<u64>), u32>,
    records: HashMap<Vec<u64>, u32>,
}

impl<'a> Data<'a> {
    fn offset(&self) -> u32 {
        u32::try_from(self.bytes.len())
            .ok()
            .filter(|&offset| offset < DATA)
            .expect("data")
    }

    fn reuse(&mut self, offset: Option<u32>) -> bool {
        offset.map(|offset| self.bytes.extend(pointer(offset))).is_some()
    }

    fn text(&mut self, value: &'a str) {
        let mut inline = Vec::new();
        inline_text(&mut inline, value);
        match self.strings.get(value) {
            Some(&offset) if pointer(offset).len() < inline.len() => {
                self.bytes.extend(pointer(offset));
            }
            _ => {
                let offset = self.offset();
                self.strings.entry(value).or_insert(offset);
                self.bytes.extend(inline);
            }
        }
    }

    fn spec(&self, table: &str, column: &str) -> &'a ColumnSpec {
        let columns = self.columns;
        &columns[&format!("{table}.{column}")]
    }

    fn value(&mut self, table: &str, column: &str, value: u64) {
        let spec = self.spec(table, column);
        if let Some(child) = &spec.link {
            return self.row(child, value);
        }
        let (index, vocabularies, output) =
            (value as usize - 1, self.vocabularies, self.output);
        if let Some(name) = &spec.vocab {
            return self.text(&vocabularies[name][index]);
        }
        if let Some(name) = &spec.flags {
            let names = vocabularies[name].iter().take(32).enumerate();
            let set: Vec<&String> = names
                .filter(|(bit, _)| index >> bit & 1 == 1)
                .map(|(_, name)| name)
                .collect();
            control(&mut self.bytes, ARRAY, set.len());
            return set.into_iter().for_each(|name| self.text(name));
        }
        let signed = spec.kind.as_deref() == Some("signed");
        match spec.kind.as_deref() {
            Some("string") => self.text(&output.strings[index]),
            Some("bool") => control(&mut self.bytes, BOOLEAN, index),
            _ if spec.scale.is_none() && !signed => {
                let kind =
                    if index as u64 > u64::from(u32::MAX) { UINT64 } else { UINT32 };
                unsigned(&mut self.bytes, kind, index as u64);
            }
            _ => {
                let number = if signed { unzigzag(index as u64) } else { index as i64 };
                let scaled = number as f64 / spec.scale.unwrap_or(1) as f64;
                control(&mut self.bytes, DOUBLE, 8);
                self.bytes.extend(scaled.to_be_bytes());
            }
        }
    }

    fn map(&mut self, entries: Vec<Entry<'a>>) {
        control(&mut self.bytes, MAP, entries.len());
        for (key, table, column, value) in entries {
            self.text(key);
            self.value(table, column, value);
        }
    }

    fn present(&self, table: &'a str, id: u64) -> Vec<Entry<'a>> {
        let output = self.output;
        let (columns, rows) = &output.tables[table];
        let row = rows[id as usize - 1].iter();
        let filled = columns.iter().zip(row).filter(|(_, value)| **value > 0);
        filled
            .map(|(column, &value)| (column.as_str(), table, column.as_str(), value))
            .collect()
    }

    fn row(&mut self, table: &'a str, id: u64) {
        if self.reuse(self.rows.get(&(table, id)).copied()) {
            return;
        }
        self.rows.insert((table, id), self.offset());
        self.map(self.present(table, id));
    }

    fn composite(&mut self, head: &'a str, link: u64, extras: Vec<Entry<'a>>) {
        let identity =
            [vec![link], extras.iter().map(|entry| entry.3).collect()].concat();
        let key = (head, identity);
        if self.reuse(self.composites.get(&key).copied()) {
            return;
        }
        self.composites.insert(key, self.offset());
        let child = self.spec("spine", head).link.as_deref().expect("link");
        let linked = if link > 0 { self.present(child, link) } else { Vec::new() };
        self.map([linked, extras].concat());
    }

    fn record(&mut self, columns: &'a [String], row: &[u64]) -> u32 {
        if row.iter().all(|&value| value == 0) {
            return EMPTY;
        }
        if let Some(&offset) = self.records.get(row) {
            return DATA | offset;
        }
        let offset = self.offset();
        self.records.insert(row.to_vec(), offset);
        let groups = groups(columns, row);
        control(&mut self.bytes, MAP, groups.len());
        for (head, link, extras) in groups {
            self.text(head);
            if !extras.is_empty() {
                self.composite(head, link, extras);
                continue;
            }
            let child = self.spec("spine", head).link.as_deref().expect("link");
            self.row(child, link);
        }
        DATA | offset
    }

    fn steps(&mut self, family: usize) -> Vec<(Address, u32)> {
        let output = self.output;
        let name = format!("spine{family}");
        let (columns, rows) = &output.tables[&name];
        let keys = &output.keys[&name];
        let hosts = format!("hosts{family}");
        let host_keys = output.keys.get(&hosts).map_or(&[][..], Vec::as_slice);
        let host_rows = output.tables.get(&hosts).map_or(&[][..], |(_, rows)| rows);
        let abuse = columns.iter().position(|column| column == "abuse");
        let after_hosts = host_keys.iter().filter_map(|key| key.checked_add(1));
        let edges = [0, IPV4_SPACE, MAPPED, MAPPED + IPV4_SPACE];
        let mut boundaries: Vec<Address> = edges
            .into_iter()
            .chain(keys.iter().copied())
            .chain(host_keys.iter().copied())
            .collect();
        boundaries.extend(after_hosts);
        boundaries.sort_unstable();
        boundaries.dedup();
        let blank = vec![0; columns.len()];
        let (mut spine, mut host) = (0, 0);
        let mut steps: Vec<(Address, u32)> = Vec::new();
        for address in boundaries {
            while keys.get(spine).is_some_and(|&key| key <= address) {
                spine += 1;
            }
            while host_keys.get(host).is_some_and(|&key| key < address) {
                host += 1;
            }
            let mut row =
                spine.checked_sub(1).map_or(blank.clone(), |index| rows[index].clone());
            if let Some(column) = abuse.filter(|_| host_keys.get(host) == Some(&address))
            {
                row[column] = host_rows[host][0];
            }
            let leaf =
                if hidden(family, address) { EMPTY } else { self.record(columns, &row) };
            if steps.last().is_none_or(|&(_, previous)| previous != leaf) {
                steps.push((address, leaf));
            }
        }
        steps
    }
}

fn hidden(family: usize, address: Address) -> bool {
    let ipv4 = address < IPV4_SPACE;
    let mapped = (MAPPED..MAPPED + IPV4_SPACE).contains(&address);
    if family == 4 { !ipv4 } else { ipv4 || mapped }
}

fn groups<'a>(columns: &'a [String], row: &[u64]) -> Vec<(&'a str, u64, Vec<Entry<'a>>)> {
    let mut heads: Vec<&str> =
        columns.iter().map(|column| column.split('.').next().expect("head")).collect();
    heads.dedup();
    let mut groups = Vec::new();
    for head in heads {
        let mut link = 0;
        let mut extras = Vec::new();
        for (column, &value) in columns.iter().zip(row).filter(|(_, value)| **value > 0) {
            if column == head {
                link = value;
            }
            let suffix =
                column.strip_prefix(head).and_then(|rest| rest.strip_prefix('.'));
            if let Some(key) = suffix {
                extras.push((key, "spine", column.as_str(), value));
            }
        }
        if link > 0 || !extras.is_empty() {
            groups.push((head, link, extras));
        }
    }
    groups
}

struct Tree<'s> {
    steps: &'s [(Address, u32)],
    nodes: Vec<[u32; 2]>,
    ipv4: u32,
}

impl Tree<'_> {
    fn build(&mut self, first: Address, bits: u32) -> u32 {
        if first == MAPPED && bits == 32 {
            return self.ipv4;
        }
        let record = self.split(first, bits);
        if first == 0 && bits == 32 {
            self.ipv4 = record;
        }
        record
    }

    fn split(&mut self, first: Address, bits: u32) -> u32 {
        let last = first | Address::MAX.checked_shr(128 - bits).unwrap_or(0);
        let index = self.steps.partition_point(|&(start, _)| start <= first) - 1;
        let uniform = self.steps.get(index + 1).is_none_or(|&(start, _)| start > last);
        let holds_alias = bits > 32 && (first..=last).contains(&MAPPED);
        if uniform && !holds_alias && bits < 128 {
            return self.steps[index].1;
        }
        let node = self.nodes.len();
        self.nodes.push([0, 0]);
        let left = self.build(first, bits - 1);
        let right = self.build(first | 1 << (bits - 1), bits - 1);
        self.nodes[node] = [left, right];
        u32::try_from(node).ok().filter(|&node| node < DATA).expect("nodes")
    }
}

fn metadata(selection: &str, node_count: u64, record_size: u64) -> Vec<u8> {
    let mut bytes = b"\xAB\xCD\xEFMaxMind.com".to_vec();
    control(&mut bytes, MAP, 9);
    for (key, kind, value) in [
        ("binary_format_major_version", UINT16, 2),
        ("binary_format_minor_version", UINT16, 0),
        ("build_epoch", UINT64, chrono::Utc::now().timestamp() as u64),
        ("ip_version", UINT16, 6),
        ("node_count", UINT32, node_count),
        ("record_size", UINT16, record_size),
    ] {
        inline_text(&mut bytes, key);
        unsigned(&mut bytes, kind, value);
    }
    inline_text(&mut bytes, "database_type");
    inline_text(&mut bytes, &format!("iplore-{selection}"));
    inline_text(&mut bytes, "description");
    control(&mut bytes, MAP, 1);
    inline_text(&mut bytes, "en");
    inline_text(
        &mut bytes,
        "iplore offline IP lookup; data licenses: \
         https://github.com/tn3w/iplore/blob/master/data/LICENSES",
    );
    inline_text(&mut bytes, "languages");
    control(&mut bytes, ARRAY, 0);
    bytes
}

pub fn write(
    output: &Output,
    columns: &BTreeMap<String, ColumnSpec>,
    vocabularies: &BTreeMap<String, Vec<String>>,
    selection: &str,
    path: &str,
) -> io::Result<()> {
    let mut data = Data {
        output,
        columns,
        vocabularies,
        bytes: Vec::new(),
        strings: HashMap::new(),
        rows: HashMap::new(),
        composites: HashMap::new(),
        records: HashMap::new(),
    };
    let mut steps = data.steps(4);
    steps.retain(|&(start, _)| start < IPV4_SPACE);
    steps.extend(data.steps(6).into_iter().filter(|&(start, _)| start >= IPV4_SPACE));
    steps.dedup_by_key(|&mut (_, leaf)| leaf);
    let mut tree = Tree { steps: &steps, nodes: Vec::new(), ipv4: EMPTY };
    tree.build(0, 128);
    let node_count = tree.nodes.len() as u64;
    let largest = node_count + 16 + data.bytes.len() as u64;
    let record_size =
        [24, 28, 32].into_iter().find(|bits| largest < 1 << bits).expect("size");
    let resolve = |record: u32| match record {
        EMPTY => node_count,
        record if record & DATA != 0 => node_count + 16 + u64::from(record & !DATA),
        record => u64::from(record),
    };
    let width = record_size as usize / 4;
    let mut bytes = Vec::with_capacity(tree.nodes.len() * width + data.bytes.len() + 512);
    for [left, right] in tree.nodes {
        let (left, right) = (resolve(left), resolve(right));
        let joined = if record_size == 28 {
            (left & 0xff_ffff) << 32 | (left >> 24) << 28 | right
        } else {
            left << record_size | right
        };
        bytes.extend(&joined.to_be_bytes()[8 - width..]);
    }
    bytes.extend([0; 16]);
    bytes.extend(&data.bytes);
    bytes.extend(metadata(selection, node_count, record_size));
    fs::write(path, &bytes)?;
    log(&format!(
        "{path}: {} bytes ({node_count} nodes, {record_size}-bit records, {} data, \
         {} records)",
        bytes.len(),
        data.bytes.len(),
        data.records.len(),
    ));
    Ok(())
}
