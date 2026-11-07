use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, Write};

use liblzma::stream::{Action, Filters, LzmaOptions, Stream};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::assemble::{Dataset, SNAPPED, Table};
use crate::spans::{Address, aligned_blocks, to_ip};
use crate::{load_json, log};

#[derive(Deserialize, Clone)]
pub struct Snap {
    exact_when: Vec<String>,
    pub prefix: HashMap<String, u32>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct ColumnSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scale: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vocab: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
}

#[derive(Deserialize, Clone)]
struct Format {
    magic: String,
    version: u8,
    blocks: HashMap<String, usize>,
    dictionary: u32,
    preset: u32,
    header_lzma: [u32; 3],
    candidates: Vec<[u32; 3]>,
    sample_blocks: usize,
    natural_order: HashMap<String, Vec<String>>,
}

#[derive(Deserialize, Clone)]
pub struct Schema {
    pub vocabularies: BTreeMap<String, Vec<String>>,
    pub tables: BTreeMap<String, BTreeMap<String, ColumnSpec>>,
    pub snap: Snap,
    format: Format,
}

#[derive(Serialize, Clone)]
pub struct Field {
    pub name: String,
    pub path: Vec<String>,
}

struct Spec {
    columns: BTreeMap<String, ColumnSpec>,
    fields: Vec<Field>,
    exact_when: Vec<String>,
    natural_order: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct Licensed {
    name: String,
    license: String,
    #[serde(default)]
    attribution: Option<String>,
}

#[derive(Deserialize)]
struct Listing {
    sources: Vec<Licensed>,
}

fn licensed() -> [Vec<Licensed>; 2] {
    [load_json::<Listing>("sources.json").sources, load_json("feeds.json")]
}

pub fn write_licenses(path: &str) -> io::Result<()> {
    let [sources, feeds] = licensed();
    let mut text = String::from(
        "iplore code: see repository license.\n\n\
         Files built by iplore contain data from every source below; each keeps its \
         own license.\nRedistributing a built file redistributes that data under \
         those terms. Every file carries\nthis list in its header (\"sources\").\n",
    );
    let attributions = sources.iter().filter_map(|entry| entry.attribution.as_deref());
    text += "\nRequired attributions\n";
    for attribution in attributions {
        text += &format!("  {attribution}\n");
    }
    for (title, entries) in
        [("Sources (data/sources.json)", &sources), ("Feeds (data/feeds.json)", &feeds)]
    {
        text += &format!("\n{title}\n");
        for entry in entries {
            text += &format!("  {:<40} {}\n", entry.name, entry.license);
        }
    }
    text += "\nEmbedded\n  US DMA labels (data/place.json metros)  none declared \
             https://github.com/simzou/nielsen-dma\n  Operator geofeeds found in RIR \
             whois objects  each publisher's terms, URL in the object\n";
    fs::write(path, text)
}

impl Schema {
    pub fn load() -> Schema {
        load_json("schema.json")
    }

    pub fn flag_names(&self) -> Vec<String> {
        self.vocabularies["flag"].clone()
    }

    fn spec(&self) -> Spec {
        let mut columns = BTreeMap::new();
        for (table, table_columns) in &self.tables {
            for (column, column_spec) in table_columns {
                columns.insert(column_key(table, column), column_spec.clone());
            }
        }
        let mut fields = Vec::new();
        self.walk("spine", "", &[], &mut fields);
        Spec {
            columns,
            fields,
            exact_when: self.snap.exact_when.clone(),
            natural_order: self.format.natural_order.clone(),
        }
    }

    fn walk(&self, table: &str, prefix: &str, path: &[String], fields: &mut Vec<Field>) {
        for (column, column_spec) in &self.tables[table] {
            let name = if prefix.is_empty() {
                column.clone()
            } else {
                format!("{prefix}.{column}")
            };
            let mut path = path.to_vec();
            path.push(column_key(table, column));
            match &column_spec.link {
                Some(child) => self.walk(child, &name, &path, fields),
                None => fields.push(Field { name, path }),
            }
        }
    }
}

pub fn term_matches(term: &str, field: &str) -> bool {
    term == "full"
        || field == term
        || field.starts_with(&format!("{term}."))
        || field.contains(&format!(".{term}."))
        || field.ends_with(&format!(".{term}"))
}

struct Plan {
    fields: Vec<Field>,
    columns: BTreeMap<String, BTreeSet<String>>,
    narrowed: HashMap<String, HashSet<u64>>,
    snapped: bool,
}

fn plan(selection: &str, spec: &Spec, dataset: &Dataset) -> Plan {
    let terms: Vec<(&str, Option<Vec<&str>>)> = selection
        .split('+')
        .map(|term| match term.split_once('=') {
            Some((field, values)) => (field, Some(values.split(',').collect())),
            None => (term, None),
        })
        .collect();
    let matching =
        |field: &Field| terms.iter().find(|(term, _)| term_matches(term, &field.name));
    let chosen: Vec<(Field, Option<Vec<&str>>)> = spec
        .fields
        .iter()
        .filter_map(|field| {
            matching(field).map(|(_, values)| (field.clone(), values.clone()))
        })
        .collect();
    let fields: Vec<Field> = chosen.iter().map(|(field, _)| field.clone()).collect();
    let mut columns: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut narrow_values: HashMap<String, HashSet<u64>> = HashMap::new();
    let mut unnarrowed: HashSet<String> = HashSet::new();
    for (field, values) in &chosen {
        for (position, column) in field.path.iter().enumerate() {
            let (table, name) = column.split_once('.').expect("table.column");
            columns.entry(table.to_string()).or_default().insert(name.to_string());
            if table == "spine" && name == "abuse" {
                columns
                    .entry("hosts".to_string())
                    .or_default()
                    .insert("abuse".to_string());
            }
            let last = position + 1 == field.path.len();
            let Some(values) = values.as_ref().filter(|_| last) else {
                unnarrowed.insert(column.clone());
                continue;
            };
            let vocabulary =
                spec.columns[column].vocab.as_ref().expect("only vocabularies narrow");
            let members = &dataset.vocabularies[vocabulary];
            let encoded = values
                .iter()
                .filter_map(|value| members.iter().position(|member| member == *value));
            narrow_values
                .entry(column.clone())
                .or_default()
                .extend(encoded.map(|index| index as u64 + 1));
        }
    }
    narrow_values.retain(|column, _| !unnarrowed.contains(column));
    let snapped = !fields
        .iter()
        .any(|field| field.path.iter().any(|column| spec.exact_when.contains(column)));
    Plan { fields, columns, narrowed: narrow_values, snapped }
}

fn table_order(spec: &Spec) -> Vec<String> {
    let mut children: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (column, column_spec) in &spec.columns {
        let table = column.split_once('.').expect("table.column").0.to_string();
        let entry = children.entry(table).or_default();
        if let Some(link) = &column_spec.link {
            entry.insert(link.clone());
        }
    }
    let mut order = Vec::new();
    let mut seen = HashSet::new();
    fn visit(
        table: &str,
        children: &BTreeMap<String, BTreeSet<String>>,
        seen: &mut HashSet<String>,
        order: &mut Vec<String>,
    ) {
        if !seen.insert(table.to_string()) {
            return;
        }
        for child in children.get(table).into_iter().flatten() {
            visit(child, children, seen, order);
        }
        order.push(table.to_string());
    }
    for table in children.keys() {
        visit(table, &children, &mut seen, &mut order);
    }
    order
}

type KeyedRows = BTreeMap<String, (Vec<Address>, Vec<Vec<u64>>)>;

struct Rebuilt {
    columns: Vec<String>,
    canonical: Table,
    old_to_canonical: Vec<u64>,
}

struct Output {
    tables: BTreeMap<String, (Vec<String>, Vec<Vec<u64>>)>,
    keys: BTreeMap<String, Vec<Address>>,
    strings: Vec<String>,
}

fn source_name(table: &str, family: Option<usize>) -> String {
    match family {
        Some(family) => format!("{table}{family}"),
        None => table.to_string(),
    }
}

fn column_key(table: &str, column: &str) -> String {
    format!("{table}.{column}")
}

fn rebuild(dataset: &Dataset, spec: &Spec, plan: &Plan) -> Output {
    let order = table_order(spec);
    let mut rebuilt: HashMap<String, Rebuilt> = HashMap::new();
    for table in order.iter().filter(|table| !matches!(table.as_str(), "spine" | "hosts"))
    {
        let Some(kept) = plan.columns.get(table) else {
            continue;
        };
        let source = &dataset.tables[table];
        let columns: Vec<String> = kept.iter().cloned().collect();
        let mut canonical =
            Table::new(&columns.iter().map(String::as_str).collect::<Vec<_>>());
        let mut old_to_canonical = Vec::with_capacity(source.rows());
        for index in 0..source.rows() {
            let row =
                project(source.row(index), source, table, &columns, spec, plan, &rebuilt);
            old_to_canonical.push(canonical.intern(row));
        }
        rebuilt.insert(table.clone(), Rebuilt { columns, canonical, old_to_canonical });
    }
    let mut spines: KeyedRows = BTreeMap::new();
    let mut hosts: KeyedRows = BTreeMap::new();
    let spine_columns: Vec<String> =
        plan.columns.get("spine").into_iter().flatten().cloned().collect();
    let host_columns: Vec<String> =
        plan.columns.get("hosts").into_iter().flatten().cloned().collect();
    for family in [4, 6] {
        let name = source_name("spine", Some(family));
        let source = &dataset.tables[&name];
        let mut keys = Vec::new();
        let mut rows: Vec<Vec<u64>> = Vec::new();
        for (index, &key) in dataset.keys[&name].iter().enumerate() {
            let row = project(
                source.row(index),
                source,
                "spine",
                &spine_columns,
                spec,
                plan,
                &rebuilt,
            );
            let repeats = rows.last().is_some_and(|previous| *previous == row);
            let leading_empty = rows.is_empty() && row.iter().all(|&value| value == 0);
            if repeats || leading_empty {
                continue;
            }
            keys.push(key);
            rows.push(row);
        }
        spines.insert(name.clone(), (keys, rows));
        if host_columns.is_empty() {
            continue;
        }
        let host_name = source_name("hosts", Some(family));
        let source = &dataset.tables[&host_name];
        let (spine_keys, spine_rows) = &spines[&name];
        let abuse_position = spine_columns.iter().position(|column| column == "abuse");
        let mut host_keys = Vec::new();
        let mut host_rows = Vec::new();
        for (index, &key) in dataset.keys[&host_name].iter().enumerate() {
            let row = project(
                source.row(index),
                source,
                "hosts",
                &host_columns,
                spec,
                plan,
                &rebuilt,
            );
            let spine_index =
                spine_keys.partition_point(|&start| start <= key).checked_sub(1);
            let range_value = spine_index
                .zip(abuse_position)
                .map_or(0, |(spine, column)| spine_rows[spine][column]);
            if row[0] == range_value {
                continue;
            }
            host_keys.push(key);
            host_rows.push(row);
        }
        hosts.insert(host_name, (host_keys, host_rows));
    }
    finalize(dataset, spec, rebuilt, spines, hosts, spine_columns, host_columns)
}

fn project(
    row: &[u64],
    source: &Table,
    table: &str,
    columns: &[String],
    spec: &Spec,
    plan: &Plan,
    rebuilt: &HashMap<String, Rebuilt>,
) -> Vec<u64> {
    columns
        .iter()
        .map(|column| {
            let source_column = if table == "spine" && column == "place" && plan.snapped {
                SNAPPED
            } else {
                column.as_str()
            };
            let value = row[source.column(source_column).expect("column")];
            let key = column_key(table, column);
            if plan.narrowed.get(&key).is_some_and(|allowed| !allowed.contains(&value)) {
                return 0;
            }
            match &spec.columns[&key].link {
                Some(child) if value > 0 => {
                    rebuilt[child].old_to_canonical[value as usize - 1]
                }
                _ => value,
            }
        })
        .collect()
}

fn finalize(
    dataset: &Dataset,
    spec: &Spec,
    rebuilt: HashMap<String, Rebuilt>,
    spines: KeyedRows,
    hosts: KeyedRows,
    spine_columns: Vec<String>,
    host_columns: Vec<String>,
) -> Output {
    let mut counts: HashMap<String, Vec<u64>> = rebuilt
        .iter()
        .map(|(table, rebuilt)| (table.clone(), vec![0u64; rebuilt.canonical.rows() + 1]))
        .collect();
    let add_references =
        |table: &str,
         columns: &[String],
         row: &[u64],
         weight: u64,
         counts: &mut HashMap<String, Vec<u64>>| {
            for (column, &value) in columns.iter().zip(row) {
                if let Some(child) = &spec.columns[&column_key(table, column)].link
                    && value > 0
                {
                    counts.get_mut(child).expect("child")[value as usize] += weight;
                }
            }
        };
    for (_, rows) in spines.values() {
        for row in rows {
            add_references("spine", &spine_columns, row, 1, &mut counts);
        }
    }
    for (_, rows) in hosts.values() {
        for row in rows {
            add_references("hosts", &host_columns, row, 1, &mut counts);
        }
    }
    let mut order = table_order(spec);
    order.reverse();
    for table in order.iter().filter(|table| rebuilt.contains_key(*table)) {
        let entry = &rebuilt[table];
        for id in 1..=entry.canonical.rows() {
            let weight = counts[table][id];
            if weight > 0 {
                let row = entry.canonical.row(id - 1).to_vec();
                add_references(table, &entry.columns, &row, weight, &mut counts);
            }
        }
    }
    let natural_orders = &spec.natural_order;
    let mut final_ids: HashMap<String, Vec<u64>> = HashMap::new();
    let mut ranked: HashMap<String, Vec<usize>> = HashMap::new();
    for (table, table_counts) in &counts {
        let mut ids: Vec<usize> =
            (1..table_counts.len()).filter(|&id| table_counts[id] > 0).collect();
        let entry = &rebuilt[table];
        let natural: Vec<usize> = natural_orders
            .get(table)
            .into_iter()
            .flatten()
            .filter_map(|column| entry.columns.iter().position(|kept| kept == column))
            .collect();
        ids.sort_by_cached_key(|&id| {
            let row = entry.canonical.row(id - 1);
            let key: Vec<u64> = natural.iter().map(|&column| row[column]).collect();
            (key, std::cmp::Reverse(table_counts[id]), id)
        });
        let mut map = vec![0u64; table_counts.len()];
        for (position, &id) in ids.iter().enumerate() {
            map[id] = position as u64 + 1;
        }
        final_ids.insert(table.clone(), map);
        ranked.insert(table.clone(), ids);
    }
    let mut string_ids: BTreeSet<&str> = BTreeSet::new();
    let is_string = |table: &str, column: &str| {
        spec.columns[&column_key(table, column)].kind.as_deref() == Some("string")
    };
    let relink = |table: &str, columns: &[String], row: &[u64]| -> Vec<u64> {
        columns
            .iter()
            .zip(row)
            .map(|(column, &value)| {
                match &spec.columns[&column_key(table, column)].link {
                    Some(child) if value > 0 => final_ids[child][value as usize],
                    _ => value,
                }
            })
            .collect()
    };
    let mut tables: BTreeMap<String, (Vec<String>, Vec<Vec<u64>>)> = BTreeMap::new();
    for (table, entry) in &rebuilt {
        let rows: Vec<Vec<u64>> = ranked[table]
            .iter()
            .map(|&id| relink(table, &entry.columns, entry.canonical.row(id - 1)))
            .collect();
        tables.insert(table.clone(), (entry.columns.clone(), rows));
    }
    let mut keys = BTreeMap::new();
    for (name, (spine_keys, rows)) in spines {
        let rows = rows.iter().map(|row| relink("spine", &spine_columns, row)).collect();
        keys.insert(name.clone(), spine_keys);
        tables.insert(name, (spine_columns.clone(), rows));
    }
    for (name, (host_keys, rows)) in hosts {
        let rows = rows.iter().map(|row| relink("hosts", &host_columns, row)).collect();
        keys.insert(name.clone(), host_keys);
        tables.insert(name, (host_columns.clone(), rows));
    }
    let logical = |name: &str| name.trim_end_matches(['4', '6']).to_string();
    for (name, (columns, rows)) in &tables {
        for (index, column) in columns.iter().enumerate() {
            if is_string(&logical(name), column) {
                string_ids.extend(
                    rows.iter().filter(|row| row[index] > 0).map(|row| {
                        dataset.strings.list[row[index] as usize - 1].as_str()
                    }),
                );
            }
        }
    }
    let strings: Vec<String> = string_ids.into_iter().map(str::to_string).collect();
    let positions: HashMap<&str, u64> = strings
        .iter()
        .enumerate()
        .map(|(index, text)| (text.as_str(), index as u64 + 1))
        .collect();
    for (name, (columns, rows)) in tables.iter_mut() {
        for (index, column) in columns.iter().enumerate() {
            if !is_string(&logical(name), column) {
                continue;
            }
            for row in rows.iter_mut().filter(|row| row[index] > 0) {
                row[index] =
                    positions[dataset.strings.list[row[index] as usize - 1].as_str()];
            }
        }
    }
    Output { tables, keys, strings }
}

fn compress(data: &[u8], settings: [u32; 3], format: &Format) -> Vec<u8> {
    let mut options = LzmaOptions::new_preset(format.preset).expect("preset");
    options
        .dict_size(format.dictionary)
        .literal_context_bits(settings[0])
        .literal_position_bits(settings[1])
        .position_bits(settings[2]);
    let mut filters = Filters::new();
    filters.lzma1(&options);
    let mut stream = Stream::new_raw_encoder(&filters).expect("encoder");
    let mut output = Vec::with_capacity(data.len() / 2 + 64);
    let mut input = data;
    loop {
        if output.capacity() - output.len() < 4096 {
            output.reserve(output.capacity().max(4096));
        }
        let before = stream.total_in();
        let status =
            stream.process_vec(input, &mut output, Action::Finish).expect("compress");
        input = &input[(stream.total_in() - before) as usize..];
        if status == liblzma::stream::Status::StreamEnd {
            return output;
        }
    }
}

fn varint(output: &mut Vec<u8>, mut value: u128) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn encode_ints(values: &[u64], delta: bool) -> Vec<u8> {
    let coded: Vec<u64> = if delta {
        let mut previous = 0u64;
        values
            .iter()
            .map(|&value| {
                let difference = value.wrapping_sub(previous) as i64;
                previous = value;
                ((difference << 1) ^ (difference >> 63)) as u64
            })
            .collect()
    } else {
        values.to_vec()
    };
    let maximum = coded.iter().copied().max().unwrap_or(0);
    let width: usize = match maximum {
        0..=0xff => 1,
        0x100..=0xffff => 2,
        0x10000..=0xffff_ffff => 4,
        _ => 8,
    };
    let mut output = vec![width as u8 | if delta { 0x80 } else { 0 }];
    for value in coded {
        output.extend_from_slice(&value.to_le_bytes()[..width]);
    }
    output
}

fn encode_keys(keys: &[Address], family: usize) -> Vec<u8> {
    let mut output = Vec::new();
    let mut previous = keys.first().copied().unwrap_or(0);
    for &key in keys {
        if family == 4 {
            varint(&mut output, key - previous);
        } else {
            let high_gap = (key >> 64) - (previous >> 64);
            varint(&mut output, high_gap);
            let low = key as u64 as u128;
            varint(
                &mut output,
                if high_gap == 0 { low - (previous as u64 as u128) } else { low },
            );
        }
        previous = key;
    }
    output
}

fn encode_strings(strings: &[String]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut previous: &[u8] = &[];
    for text in strings {
        let bytes = text.as_bytes();
        let shared = previous.iter().zip(bytes).take_while(|(a, b)| a == b).count();
        varint(&mut output, shared as u128);
        varint(&mut output, (bytes.len() - shared) as u128);
        output.extend_from_slice(&bytes[shared..]);
        previous = bytes;
    }
    output
}

struct Section {
    name: String,
    encoding: &'static str,
    count: usize,
    block: usize,
    settings: [u32; 3],
    family: Option<usize>,
    firsts: Vec<String>,
    blocks: Vec<Vec<u8>>,
    raw: usize,
}

fn best_settings(blocks: &[Vec<u8>], format: &Format) -> ([u32; 3], usize) {
    let sample: Vec<u8> =
        blocks.iter().take(format.sample_blocks).flatten().copied().collect();
    format
        .candidates
        .par_iter()
        .map(|&settings| (settings, compress(&sample, settings, format).len()))
        .min_by_key(|&(settings, size)| (size, settings))
        .expect("candidates")
}

fn int_section(name: String, values: &[u64], format: &Format) -> Section {
    let too_wide = values.iter().any(|&value| value > u64::from(u32::MAX));
    assert!(!too_wide, "{name}: value exceeds 32 bits");
    let block = format.blocks["ints"];
    let chunks: Vec<&[u64]> = values.chunks(block).collect();
    let plain: Vec<Vec<u8>> =
        chunks.iter().map(|chunk| encode_ints(chunk, false)).collect();
    let delta: Vec<Vec<u8>> =
        chunks.iter().map(|chunk| encode_ints(chunk, true)).collect();
    let (plain_settings, plain_size) = best_settings(&plain, format);
    let (delta_settings, delta_size) = best_settings(&delta, format);
    let (blocks, settings) = if delta_size < plain_size {
        (delta, delta_settings)
    } else {
        (plain, plain_settings)
    };
    let raw = blocks.iter().map(Vec::len).sum();
    Section {
        name,
        encoding: "ints",
        count: values.len(),
        block,
        settings,
        family: None,
        firsts: Vec::new(),
        blocks,
        raw,
    }
}

fn key_section(
    name: String,
    keys: &[Address],
    family: usize,
    format: &Format,
) -> Section {
    let block = format.blocks["keys"];
    let blocks: Vec<Vec<u8>> =
        keys.chunks(block).map(|chunk| encode_keys(chunk, family)).collect();
    let firsts = keys.chunks(block).map(|chunk| chunk[0].to_string()).collect();
    let (settings, _) = best_settings(&blocks, format);
    let raw = blocks.iter().map(Vec::len).sum();
    Section {
        name,
        encoding: "keys",
        count: keys.len(),
        block,
        settings,
        family: Some(family),
        firsts,
        blocks,
        raw,
    }
}

fn string_section(strings: &[String], format: &Format) -> Section {
    let block = format.blocks["strings"];
    let blocks: Vec<Vec<u8>> = strings.chunks(block).map(encode_strings).collect();
    let (settings, _) = best_settings(&blocks, format);
    let raw = blocks.iter().map(Vec::len).sum();
    let name = "strings".to_string();
    Section {
        name,
        encoding: "strings",
        count: strings.len(),
        block,
        settings,
        family: None,
        firsts: Vec::new(),
        blocks,
        raw,
    }
}

pub fn write(
    dataset: &Dataset,
    schema: &Schema,
    selection: &str,
    path: &str,
) -> std::io::Result<()> {
    let spec = schema.spec();
    let format = &schema.format;
    let plan = plan(selection, &spec, dataset);
    if plan.fields.is_empty() || selection.contains('/') {
        return Err(std::io::Error::other(format!(
            "selection {selection} matches no field"
        )));
    }
    let output = rebuild(dataset, &spec, &plan);
    let mut sections: Vec<Section> = Vec::new();
    let mut tables_header = serde_json::Map::new();
    for (name, (columns, rows)) in &output.tables {
        let logical = name.trim_end_matches(['4', '6']);
        let mut table_header = serde_json::Map::new();
        table_header.insert("rows".into(), json!(rows.len()));
        if let Some(keys) = output.keys.get(name) {
            let family = if name.ends_with('4') { 4 } else { 6 };
            table_header.insert("keys".into(), json!(sections.len()));
            sections.push(key_section(format!("{name}.keys"), keys, family, format));
        }
        let mut columns_header = serde_json::Map::new();
        for (index, column) in columns.iter().enumerate() {
            let values: Vec<u64> = rows.iter().map(|row| row[index]).collect();
            let mut column_spec =
                serde_json::to_value(&spec.columns[&column_key(logical, column)])
                    .expect("spec");
            column_spec["section"] = json!(sections.len());
            columns_header.insert(column.clone(), column_spec);
            sections.push(int_section(format!("{name}.{column}"), &values, format));
        }
        table_header.insert("columns".into(), columns_header.into());
        tables_header.insert(name.clone(), table_header.into());
    }
    sections.push(string_section(&output.strings, format));
    let compressed: Vec<Vec<Vec<u8>>> = sections
        .par_iter()
        .map(|section| {
            section
                .blocks
                .par_iter()
                .map(|block| compress(block, section.settings, format))
                .collect()
        })
        .collect();
    let mut data = Vec::new();
    let mut sections_header = Vec::new();
    log(&format!("{selection}: section breakdown"));
    log(&format!(
        "  {:<28} {:>9} {:>11} {:>11} {:>8}",
        "section", "count", "raw", "stored", "B/entry"
    ));
    let mut stored_total = 0usize;
    for (section, blocks) in sections.iter().zip(&compressed) {
        let mut offsets = Vec::new();
        let start = data.len();
        for block in blocks {
            offsets.push(data.len());
            data.extend_from_slice(block);
        }
        offsets.push(data.len());
        let stored = data.len() - start;
        stored_total += stored;
        let per_entry = stored as f64 / section.count.max(1) as f64;
        log(&format!(
            "  {:<28} {:>9} {:>11} {:>11} {:>8.3}",
            section.name, section.count, section.raw, stored, per_entry
        ));
        let mut header = json!({
            "name": section.name,
            "encoding": section.encoding,
            "count": section.count,
            "block": section.block,
            "lzma": section.settings,
            "offsets": offsets,
        });
        if let Some(family) = section.family {
            header["family"] = json!(family);
            header["firsts"] = json!(section.firsts);
        }
        sections_header.push(header);
    }
    let sources: BTreeMap<String, String> = licensed()
        .into_iter()
        .flatten()
        .map(|entry| (entry.name, entry.license))
        .collect();
    let header = json!({
        "format": format.version,
        "selection": selection,
        "built": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "dictionary": format.dictionary,
        "fields": plan.fields,
        "vocabularies": dataset.vocabularies,
        "tables": tables_header,
        "sections": sections_header,
        "sources": sources,
    });
    let header = compress(&serde_json::to_vec(&header)?, format.header_lzma, format);
    let mut file = fs::File::create(path)?;
    file.write_all(format.magic.as_bytes())?;
    file.write_all(&[0, format.version])?;
    file.write_all(&(header.len() as u32).to_le_bytes())?;
    file.write_all(&header)?;
    file.write_all(&data)?;
    let total = format.magic.len() + 6 + header.len() + data.len();
    log(&format!("  {:<28} {:>9} {:>11} {:>11}", "header", "", "", header.len()));
    log(&format!("{path}: {total} bytes ({stored_total} data)"));
    Ok(())
}

pub fn write_blocklist(dataset: &Dataset, path: &str) -> std::io::Result<()> {
    let mut lines = Vec::new();
    let mut addresses = [0u128; 2];
    for (family_slot, family) in [4usize, 6].into_iter().enumerate() {
        for span in &dataset.blocklist[family_slot] {
            addresses[family_slot] += span.last - span.first + 1;
            for (start, length) in aligned_blocks(family, span.first, span.last) {
                lines.push(format!("{}/{length}", to_ip(family, start)));
            }
        }
    }
    let date = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let header = format!(
        "#\n# iplore blocklist\n#\n\
         # Addresses reported at risk >= 0.40 by their own claims and\n\
         # anonymising services named by current published or measured lists.\n#\n\
         # Generated: {date}\n# Entries: {}\n\
         # IPv4 addresses: {}\n# IPv6 addresses: {}\n#\n",
        lines.len(),
        addresses[0],
        addresses[1]
    );
    fs::write(path, header + &lines.join("\n") + "\n")?;
    log(&format!("{path}: {} CIDRs", lines.len()));
    Ok(())
}
