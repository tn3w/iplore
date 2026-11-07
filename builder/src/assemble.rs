use std::collections::{BTreeMap, HashMap};
use std::fs;

use crate::abuse::{Abuse, Record, subtract};
use crate::fetch::input_path;
use crate::geo::{Geography, Places};
use crate::network::{NetworkRules, NetworkSpan, Networks, Operator, Registration};
use crate::spans::{
    Address, Families, Span, bits, lookup, parse_range, push_merged, slot,
};
use crate::write::Schema;

pub const SNAPPED: &str = "place_snapped";

pub struct Table {
    pub columns: Vec<String>,
    pub values: Vec<u64>,
    index: HashMap<Vec<u64>, u64>,
}

impl Table {
    pub fn new(columns: &[&str]) -> Table {
        let columns = columns.iter().map(|column| column.to_string()).collect();
        Table { columns, values: Vec::new(), index: HashMap::new() }
    }

    pub fn width(&self) -> usize {
        self.columns.len()
    }

    pub fn rows(&self) -> usize {
        self.values.len() / self.width().max(1)
    }

    pub fn row(&self, index: usize) -> &[u64] {
        &self.values[index * self.width()..(index + 1) * self.width()]
    }

    pub fn column(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|column| column == name)
    }

    pub fn push(&mut self, row: &[u64]) {
        self.values.extend_from_slice(row);
    }

    pub fn intern(&mut self, row: Vec<u64>) -> u64 {
        if row.iter().all(|&value| value == 0) {
            return 0;
        }
        if let Some(&id) = self.index.get(&row) {
            return id;
        }
        self.values.extend_from_slice(&row);
        let id = self.rows() as u64;
        self.index.insert(row, id);
        id
    }
}

#[derive(Default)]
pub struct Strings {
    pub list: Vec<String>,
    ids: HashMap<String, u64>,
}

impl Strings {
    pub fn id(&mut self, text: Option<&str>) -> u64 {
        let Some(text) = text.filter(|text| !text.is_empty()) else {
            return 0;
        };
        if let Some(&id) = self.ids.get(text) {
            return id;
        }
        self.list.push(text.to_string());
        let id = self.list.len() as u64;
        self.ids.insert(text.to_string(), id);
        id
    }
}

pub struct Dataset {
    pub tables: BTreeMap<String, Table>,
    pub keys: BTreeMap<String, Vec<Address>>,
    pub strings: Strings,
    pub vocabularies: BTreeMap<String, Vec<String>>,
    pub blocklist: Families<()>,
}

pub fn int(value: Option<u64>) -> u64 {
    value.map_or(0, |value| value + 1)
}

pub fn signed(value: Option<i64>) -> u64 {
    value.map_or(0, |value| ((value << 1) ^ (value >> 63)) as u64 + 1)
}

enum Cell<'a> {
    Int(Option<u64>),
    Signed(Option<i64>),
    Text(Option<&'a str>),
    Vocab(&'a str, Option<&'a str>),
    Bool(bool),
    Link(u64),
}

struct Builder {
    tables: BTreeMap<String, Table>,
    strings: Strings,
    vocabularies: BTreeMap<String, Vec<String>>,
}

impl Builder {
    fn encode(&mut self, cell: Cell) -> u64 {
        match cell {
            Cell::Int(value) => int(value),
            Cell::Signed(value) => signed(value),
            Cell::Text(value) => self.strings.id(value),
            Cell::Vocab(name, value) => {
                let members = &self.vocabularies[name];
                let position = value.map(|value| {
                    members.iter().position(|member| member == value).unwrap_or_else(
                        || panic!("{value} missing from vocabulary {name}"),
                    )
                });
                int(position.map(|position| position as u64))
            }
            Cell::Bool(value) => int(Some(u64::from(value))),
            Cell::Link(value) => value,
        }
    }

    fn row(&mut self, table: &str, cells: Vec<(&str, Cell)>) -> u64 {
        let mut row = vec![0; self.tables[table].width()];
        for (name, cell) in cells {
            let column = self.tables[table].column(name);
            let index = column.unwrap_or_else(|| panic!("missing column {table}.{name}"));
            row[index] = self.encode(cell);
        }
        self.tables.get_mut(table).expect("table").intern(row)
    }
}

pub fn reserved_spans(rules: &NetworkRules) -> Families<()> {
    let reserved = &rules.reserved;
    let mut cidrs: Vec<String> = reserved.extra.clone();
    for registry in &reserved.registries {
        let text = fs::read_to_string(input_path(registry)).unwrap_or_default();
        for columns in text.lines().skip(1).map(split_csv) {
            let reachable = columns.get(reserved.reachable_column);
            let reachable =
                reachable.map(|value| value.split('[').next().unwrap_or(value).trim());
            if !reachable.is_some_and(|value| {
                reserved.unreachable.iter().any(|known| known == value)
            }) {
                continue;
            }
            let blocks = columns[0].split(',');
            cidrs.extend(
                blocks.map(|cidr| cidr.split('[').next().unwrap_or(cidr).trim().into()),
            );
        }
    }
    let mut spans: Families<()> = [Vec::new(), Vec::new()];
    for cidr in cidrs {
        let mapped_v4 = cidr.contains(':') && !cidr.contains('.');
        let Some((family, first, last)) = parse_range(&cidr) else {
            continue;
        };
        if !(mapped_v4 && family == 4) {
            spans[slot(family)].push(Span { first, last, value: () });
        }
    }
    spans.map(|mut family| {
        family.sort_by_key(|span| span.first);
        let mut merged: Vec<Span<()>> = Vec::new();
        for span in family {
            match merged.last_mut() {
                Some(previous) if span.first <= previous.last.saturating_add(1) => {
                    previous.last = previous.last.max(span.last);
                }
                _ => merged.push(span),
            }
        }
        merged
    })
}

fn split_csv(line: &str) -> Vec<String> {
    let mut columns = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '"' if quoted && characters.peek() == Some(&'"') => {
                current.push('"');
                characters.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => columns.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    columns.push(current);
    columns
}

pub fn assemble(
    geography: &Geography,
    places: &Places,
    networks: &Networks,
    abuse: &Abuse,
    schema: &Schema,
) -> Dataset {
    let mut tables = BTreeMap::new();
    for (name, columns) in &schema.tables {
        let mut names: Vec<&str> = columns.keys().map(String::as_str).collect();
        if name == "spine" {
            names.push(SNAPPED);
        }
        tables.insert(name.clone(), Table::new(&names));
    }
    let vocabularies = schema.vocabularies.clone();
    let mut builder = Builder { tables, strings: Strings::default(), vocabularies };
    let country_links: HashMap<String, u64> = geography
        .countries
        .keys()
        .map(|code| (code.clone(), country_row(&mut builder, geography, code)))
        .collect();
    let point_links = place_rows(&mut builder, geography, places, &country_links);
    let network_links = network_rows(&mut builder, networks, abuse);
    let abuse_links: Vec<u64> =
        abuse.records.iter().map(|record| abuse_row(&mut builder, record)).collect();
    let reserved = reserved_spans(&networks.rules);
    let mut keys = BTreeMap::new();
    for (family_slot, family) in [4usize, 6].into_iter().enumerate() {
        let exact = relink(&places.exact[family_slot], &point_links);
        let snapped = snap(&exact, family, schema.snap.prefix[&family.to_string()]);
        let layers = Layers {
            place: exact,
            snapped,
            network: network_layer(&networks.spans[family_slot], &network_links),
            abuse: relink(&abuse.spans[family_slot], &abuse_links),
            registry: registry_layer(&mut builder, &networks.registry[family_slot]),
            reserved: reserved[family_slot].clone(),
        };
        let (spine_keys, spine) = merge(&layers, &builder.tables["spine"]);
        keys.insert(format!("spine{family}"), spine_keys);
        builder.tables.insert(format!("spine{family}"), spine);
        let mut hosts = Table::new(&["abuse"]);
        let mut host_keys = Vec::new();
        let mut sorted = abuse.hosts[family_slot].clone();
        sorted.sort_unstable();
        for (address, record) in sorted {
            if lookup(&reserved[family_slot], address).is_none() {
                host_keys.push(address);
                hosts.push(&[abuse_links[record as usize]]);
            }
        }
        keys.insert(format!("hosts{family}"), host_keys);
        builder.tables.insert(format!("hosts{family}"), hosts);
    }
    builder.tables.remove("spine");
    builder.tables.remove("hosts");
    let mut blocklist = abuse.blocklist.clone();
    for (family_slot, family) in blocklist.iter_mut().enumerate() {
        subtract(family, &reserved[family_slot]);
    }
    Dataset {
        tables: builder.tables,
        keys,
        strings: builder.strings,
        vocabularies: builder.vocabularies,
        blocklist,
    }
}

fn network_layer(spans: &[Span<NetworkSpan>], links: &[u64]) -> Vec<Span<[u64; 3]>> {
    let row = |value: &NetworkSpan| {
        let prefix = int(value.prefix.map(u64::from));
        let rpki = int(value.rpki.map(u64::from));
        [links[value.network as usize], prefix, rpki]
    };
    let span = |span: &Span<NetworkSpan>| Span {
        first: span.first,
        last: span.last,
        value: row(&span.value),
    };
    spans.iter().map(span).collect()
}

fn registry_layer(
    builder: &mut Builder,
    spans: &[Span<Registration>],
) -> Vec<Span<[u64; 3]>> {
    let mut output = Vec::new();
    for span in spans {
        let registration = &span.value;
        let code = String::from_utf8_lossy(&registration.country).to_string();
        let code = (code.len() == 2 && code != "ZZ").then_some(code.as_str());
        let value = [
            int(Some(u64::from(registration.rir))),
            builder.strings.id(code),
            int(registration.year.map(u64::from)),
        ];
        output.push(Span { first: span.first, last: span.last, value });
    }
    output
}

fn relink(spans: &[Span<u32>], links: &[u64]) -> Vec<Span<u64>> {
    let mut output = Vec::new();
    for span in spans {
        push_merged(&mut output, span.first, span.last, links[span.value as usize]);
    }
    output
}

fn country_row(builder: &mut Builder, geography: &Geography, code: &str) -> u64 {
    let country = &geography.countries[code];
    let rules = &geography.rules;
    let calling_code = country.calling_code.trim_start_matches('+');
    let calling_code = (!calling_code.is_empty()).then(|| format!("+{calling_code}"));
    let present = |value: &String| (!value.is_empty()).then(|| value.clone());
    let (name, continent) = (present(&country.name), present(&country.continent));
    let currency = present(&country.currency);
    let languages = present(&country.languages);
    builder.row(
        "country",
        vec![
            ("code", Cell::Text(Some(code))),
            ("name", Cell::Text(name.as_deref())),
            ("continent", Cell::Text(continent.as_deref())),
            ("currency", Cell::Text(currency.as_deref())),
            ("calling_code", Cell::Text(calling_code.as_deref())),
            ("languages", Cell::Text(languages.as_deref())),
            ("eu", Cell::Bool(rules.eu.iter().any(|member| member == code))),
        ],
    )
}

fn place_rows(
    builder: &mut Builder,
    geography: &Geography,
    places: &Places,
    country_links: &HashMap<String, u64>,
) -> Vec<u64> {
    let mut region_links: HashMap<u32, u64> = HashMap::new();
    let mut city_links: HashMap<u32, u64> = HashMap::new();
    let mut links = Vec::with_capacity(places.points.len());
    for point in &places.points {
        let country_code = &places.country_codes[point.country as usize];
        let country = country_links.get(country_code).copied().unwrap_or(0);
        let region = point.region.map_or(0, |region| {
            *region_links.entry(region).or_insert_with(|| {
                region_row(builder, geography, &places.region_keys[region as usize])
            })
        });
        let city = point.city.map_or(0, |city| {
            *city_links
                .entry(city)
                .or_insert_with(|| city_row(builder, geography, places, city as usize))
        });
        let cells = vec![
            ("lat", Cell::Signed(Some(i64::from(point.lat)))),
            ("lon", Cell::Signed(Some(i64::from(point.lon)))),
            ("accuracy", Cell::Int(Some(u64::from(point.accuracy)))),
            ("confidence", Cell::Int(Some(u64::from(point.confidence)))),
            ("city", Cell::Link(city)),
            ("region", Cell::Link(region)),
            ("country", Cell::Link(country)),
        ];
        links.push(builder.row("place", cells));
    }
    links
}

fn region_row(builder: &mut Builder, geography: &Geography, key: &str) -> u64 {
    let Some(region) = geography.regions.get(key) else {
        return 0;
    };
    let cells = vec![
        ("name", Cell::Text(Some(&region.name))),
        ("iso", Cell::Text(region.iso.as_deref())),
        ("geonames_id", Cell::Int(Some(u64::from(region.geonames_id)))),
    ];
    builder.row("region", cells)
}

fn city_row(
    builder: &mut Builder,
    geography: &Geography,
    places: &Places,
    index: usize,
) -> u64 {
    let city = &geography.cities[index];
    let rules = &geography.rules;
    let district = city.district.as_ref().and_then(|key| geography.districts.get(key));
    let metro =
        places.metros.get(&index).and_then(|code| rules.metros.get(&code.to_string()));
    let cells = vec![
        ("name", Cell::Text(Some(&city.name))),
        ("geonames_id", Cell::Int(Some(u64::from(city.geonames_id)))),
        ("population", Cell::Int((city.population > 0).then_some(city.population))),
        ("district", Cell::Text(district.map(String::as_str))),
        ("postal", Cell::Text(geography.postal.get(&index).map(String::as_str))),
        ("metro", Cell::Text(metro.map(String::as_str))),
        ("timezone", Cell::Text(Some(&city.timezone))),
    ];
    builder.row("city", cells)
}

fn network_rows(builder: &mut Builder, networks: &Networks, abuse: &Abuse) -> Vec<u64> {
    let mut operator_links: HashMap<&Operator, u64> = HashMap::new();
    let mut links = Vec::with_capacity(networks.rows.len());
    for (index, row) in networks.rows.iter().enumerate() {
        let operator = *operator_links
            .entry(&row.operator)
            .or_insert_with(|| operator_row(builder, &row.operator));
        let risk = abuse.network_risk.get(&(index as u32)).map(|&risk| u64::from(risk));
        let cells = vec![
            ("asn", Cell::Int(row.asn.map(u64::from))),
            ("handle", Cell::Text(row.handle.as_deref())),
            ("users", Cell::Int(row.users)),
            ("mobile_code", Cell::Text(row.mobile_code.as_deref())),
            ("risk", Cell::Int(risk)),
            ("operator", Cell::Link(operator)),
        ];
        links.push(builder.row("network", cells));
    }
    links
}

fn operator_row(builder: &mut Builder, operator: &Operator) -> u64 {
    let cells = vec![
        ("company", Cell::Text(operator.company.as_deref())),
        ("category", Cell::Vocab("category", operator.category.as_deref())),
        ("website", Cell::Text(operator.website.as_deref())),
        ("address", Cell::Text(operator.address.as_deref())),
        ("country", Cell::Text(operator.country.as_deref())),
        ("abuse_email", Cell::Text(operator.abuse_email.as_deref())),
        ("since", Cell::Int(operator.since)),
        ("tier", Cell::Int(operator.tier)),
        ("cone", Cell::Int(operator.cone)),
    ];
    builder.row("operator", cells)
}

fn abuse_row(builder: &mut Builder, record: &Record) -> u64 {
    let cells = vec![
        ("risk", Cell::Int(record.risk.map(u64::from))),
        ("threat", Cell::Vocab("threat", record.threat.as_deref())),
        ("reports", Cell::Int(record.reports.map(u64::from))),
        ("last_seen_days", Cell::Int(record.last_seen_days.map(u64::from))),
        ("service", Cell::Vocab("service", record.service.as_deref())),
        ("evidence", Cell::Vocab("evidence", record.evidence.as_deref())),
        ("provider", Cell::Text(record.provider.as_deref())),
        ("user_type", Cell::Vocab("category", record.user_type.as_deref())),
        ("flags", Cell::Int((record.flags > 0).then_some(record.flags))),
    ];
    builder.row("abuse", cells)
}

struct Layers {
    place: Vec<Span<u64>>,
    snapped: Vec<Span<u64>>,
    network: Vec<Span<[u64; 3]>>,
    abuse: Vec<Span<u64>>,
    registry: Vec<Span<[u64; 3]>>,
    reserved: Vec<Span<()>>,
}

struct Cursor<'a, T> {
    spans: &'a [Span<T>],
    position: usize,
}

impl<'a, T> Cursor<'a, T> {
    fn new(spans: &'a [Span<T>]) -> Self {
        Cursor { spans, position: 0 }
    }

    fn at(&mut self, address: Address) -> Option<&'a T> {
        while self.position < self.spans.len() && self.spans[self.position].last < address
        {
            self.position += 1;
        }
        let span = self.spans.get(self.position)?;
        (span.first <= address).then_some(&span.value)
    }
}

fn boundaries<T>(spans: &[Span<T>], output: &mut Vec<Address>) {
    for span in spans {
        output.push(span.first);
        output.extend(span.last.checked_add(1));
    }
}

fn merge(layers: &Layers, spine: &Table) -> (Vec<Address>, Table) {
    let mut points = Vec::new();
    boundaries(&layers.place, &mut points);
    boundaries(&layers.snapped, &mut points);
    boundaries(&layers.network, &mut points);
    boundaries(&layers.abuse, &mut points);
    boundaries(&layers.registry, &mut points);
    boundaries(&layers.reserved, &mut points);
    points.sort_unstable();
    points.dedup();
    let column =
        |name: &str| spine.column(name).unwrap_or_else(|| panic!("spine.{name}"));
    let network_columns = ["network", "network.prefix", "network.rpki"].map(column);
    let registry_columns = ["network.rir", "network.country", "network.year"].map(column);
    let single_columns = ["place", SNAPPED, "abuse"].map(column);
    let mut single = [
        Cursor::new(&layers.place),
        Cursor::new(&layers.snapped),
        Cursor::new(&layers.abuse),
    ];
    let mut network = Cursor::new(&layers.network);
    let mut registry = Cursor::new(&layers.registry);
    let mut reserved = Cursor::new(&layers.reserved);
    let mut table =
        Table::new(&spine.columns.iter().map(String::as_str).collect::<Vec<_>>());
    let mut keys = Vec::new();
    let mut previous: Option<Vec<u64>> = None;
    for address in points {
        let mut row = vec![0u64; table.width()];
        if reserved.at(address).is_none() {
            for (index, cursor) in single_columns.iter().zip(single.iter_mut()) {
                row[*index] = cursor.at(address).copied().unwrap_or(0);
            }
            let network_values = network.at(address).copied().unwrap_or_default();
            for (index, value) in network_columns.iter().zip(network_values) {
                row[*index] = value;
            }
            let registry_values = registry.at(address).copied().unwrap_or_default();
            for (index, value) in registry_columns.iter().zip(registry_values) {
                row[*index] = value;
            }
        }
        if previous.as_ref() == Some(&row) {
            continue;
        }
        keys.push(address);
        table.push(&row);
        previous = Some(row);
    }
    (keys, table)
}

pub fn snap(spans: &[Span<u64>], family: usize, prefix: u32) -> Vec<Span<u64>> {
    let host_bits = bits(family) - prefix;
    let size: Address = 1 << host_bits;
    let mut output: Vec<Span<u64>> = Vec::new();
    let mut votes: Vec<(u64, Address)> = Vec::new();
    let mut open: Option<Address> = None;
    for span in spans {
        let mut start = span.first;
        loop {
            let block = start >> host_bits;
            let block_last = (block << host_bits) | (size - 1);
            let end = if start % size == 0 && span.last >= block_last {
                flush_votes(&mut output, &mut votes, open.take(), host_bits);
                let after = span.last.checked_add(1);
                let whole_last =
                    after.map_or(span.last, |after| after - after % size - 1);
                push_merged(&mut output, start, whole_last, span.value);
                whole_last
            } else {
                if open != Some(block) {
                    flush_votes(&mut output, &mut votes, open.replace(block), host_bits);
                }
                let end = span.last.min(block_last);
                add_vote(&mut votes, span.value, end - start + 1);
                end
            };
            match end.checked_add(1) {
                Some(next) if next <= span.last => start = next,
                _ => break,
            }
        }
    }
    flush_votes(&mut output, &mut votes, open, host_bits);
    output
}

fn add_vote(votes: &mut Vec<(u64, Address)>, value: u64, mass: Address) {
    match votes.iter_mut().find(|(candidate, _)| *candidate == value) {
        Some((_, total)) => *total += mass,
        None => votes.push((value, mass)),
    }
}

fn flush_votes(
    output: &mut Vec<Span<u64>>,
    votes: &mut Vec<(u64, Address)>,
    block: Option<Address>,
    host_bits: u32,
) {
    let winner =
        votes.iter().max_by_key(|(value, mass)| (*mass, std::cmp::Reverse(*value)));
    if let (Some(block), Some(&(value, _))) = (block, winner) {
        let first = block << host_bits;
        push_merged(output, first, first | ((1 << host_bits) - 1), value);
    }
    votes.clear();
}
