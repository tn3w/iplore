use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use maxminddb::{Reader, WithinOptions};
use serde::Deserialize;

use crate::fetch::input_path;
use crate::spans::{
    Address, Families, Span, from_ip, narrowest, push_merged, slot, sweep,
};
use crate::text::{Text, decode_line};
use crate::{load_json, log};

#[derive(Deserialize)]
pub struct PlaceRules {
    snap_radii_km: Vec<f64>,
    snap_fallback_km: f64,
    name_match_km: f64,
    geofeed_confidence: u32,
    confidence: ConfidenceRules,
    accuracy_floor_percentile: usize,
    postal_radius_km: f64,
    pub holdout_every: usize,
    region_fixes: HashMap<String, String>,
    pub eu: Vec<String>,
    pub metros: HashMap<String, String>,
}

#[derive(Deserialize)]
struct ConfidenceRules {
    same_city: u32,
    distance_km: Vec<(f64, u32)>,
    farther: u32,
    country_agrees: u32,
    country_disagrees: u32,
    single_source_region: u32,
    single_source_country: u32,
    borrowed_city: u32,
}

pub struct City {
    pub geonames_id: u32,
    pub name: String,
    pub ascii: String,
    pub lat: f64,
    pub lon: f64,
    pub country: String,
    pub region: Option<String>,
    pub district: Option<String>,
    pub population: u64,
    pub timezone: String,
}

pub struct Region {
    pub name: String,
    pub geonames_id: u32,
    pub iso: Option<String>,
}

pub struct Country {
    pub code: String,
    pub name: String,
    pub continent: String,
    pub currency: String,
    pub calling_code: String,
    pub languages: String,
}

type PostalEntry = (String, f64, f64);
type AllowedRanges<'a> = (Vec<(usize, Address, Address)>, HashSet<&'a str>);

pub struct Geography {
    pub rules: PlaceRules,
    pub cities: Vec<City>,
    city_by_id: HashMap<u32, usize>,
    names: HashMap<(String, String), Vec<usize>>,
    grid: HashMap<(i32, i32), Vec<usize>>,
    pub regions: HashMap<String, Region>,
    region_by_iso: HashMap<String, String>,
    region_by_name: HashMap<(String, String), String>,
    pub districts: HashMap<String, String>,
    pub countries: BTreeMap<String, Country>,
    largest_city: HashMap<String, usize>,
    pub postal: HashMap<usize, String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Point {
    pub lat: i32,
    pub lon: i32,
    pub accuracy: u32,
    pub country: u16,
    pub region: Option<u32>,
    pub city: Option<u32>,
    pub confidence: u32,
}

pub struct Places {
    pub points: Vec<Point>,
    pub exact: Families<u32>,
    pub region_keys: Vec<String>,
    pub country_codes: Vec<String>,
    pub metros: HashMap<usize, u16>,
}

#[derive(Default)]
struct Interner {
    points: Vec<Point>,
    ids: HashMap<Point, u32>,
    region_keys: Vec<String>,
    region_ids: HashMap<String, u32>,
    country_codes: Vec<String>,
    country_ids: HashMap<String, u16>,
}

impl Interner {
    fn point(&mut self, point: Point) -> u32 {
        if let Some(&id) = self.ids.get(&point) {
            return id;
        }
        self.points.push(point);
        let id = self.points.len() as u32 - 1;
        self.ids.insert(point, id);
        id
    }

    fn region(&mut self, key: &str) -> u32 {
        if let Some(&id) = self.region_ids.get(key) {
            return id;
        }
        self.region_keys.push(key.to_string());
        let id = self.region_keys.len() as u32 - 1;
        self.region_ids.insert(key.to_string(), id);
        id
    }

    fn country(&mut self, code: &str) -> u16 {
        if let Some(&id) = self.country_ids.get(code) {
            return id;
        }
        self.country_codes.push(code.to_string());
        let id = self.country_codes.len() as u16 - 1;
        self.country_ids.insert(code.to_string(), id);
        id
    }
}

pub fn distance_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (phi1, phi2) = (lat1.to_radians(), lat2.to_radians());
    let half_phi = (lat2 - lat1).to_radians() / 2.0;
    let half_lambda = (lon2 - lon1).to_radians() / 2.0;
    let chord =
        half_phi.sin().powi(2) + phi1.cos() * phi2.cos() * half_lambda.sin().powi(2);
    12742.0 * chord.sqrt().min(1.0).asin()
}

fn cell(lat: f64, lon: f64) -> (i32, i32) {
    (lat.floor() as i32, lon.floor() as i32)
}

fn tab_columns(path: &Path, mut visit: impl FnMut(&[&str])) {
    let bytes = fs::read(path).unwrap_or_default();
    for line in bytes.split(|&byte| byte == b'\n') {
        let line = decode_line(line);
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let columns: Vec<&str> = line.split('\t').collect();
        visit(&columns);
    }
}

impl Geography {
    pub fn load(text: &Text) -> Geography {
        let rules: PlaceRules = load_json("place.json");
        let mut geography = Geography {
            rules,
            cities: Vec::new(),
            city_by_id: HashMap::new(),
            names: HashMap::new(),
            grid: HashMap::new(),
            regions: HashMap::new(),
            region_by_iso: HashMap::new(),
            region_by_name: HashMap::new(),
            districts: HashMap::new(),
            countries: BTreeMap::new(),
            largest_city: HashMap::new(),
            postal: HashMap::new(),
        };
        geography.load_countries();
        geography.load_regions(text);
        geography.load_cities(text);
        geography.load_postal();
        log(&format!(
            "geonames: {} cities, {} regions, {} districts, {} countries",
            geography.cities.len(),
            geography.regions.len(),
            geography.districts.len(),
            geography.countries.len()
        ));
        geography
    }

    fn load_countries(&mut self) {
        tab_columns(&input_path("geonames_countries"), |columns| {
            if columns.len() < 16 {
                return;
            }
            let country = Country {
                code: columns[0].to_string(),
                name: columns[4].to_string(),
                continent: columns[8].to_string(),
                currency: columns[10].to_string(),
                calling_code: columns[12].to_string(),
                languages: columns[15].to_string(),
            };
            self.countries.insert(country.code.clone(), country);
        });
    }

    fn load_regions(&mut self, text: &Text) {
        #[derive(Deserialize)]
        struct IsoRegion {
            code: String,
            name: String,
        }
        #[derive(Deserialize)]
        struct IsoRegions {
            #[serde(rename = "3166-2")]
            regions: Vec<IsoRegion>,
        }
        let iso_text = fs::read_to_string(input_path("iso_3166_2")).unwrap_or_default();
        let iso: Vec<IsoRegion> = serde_json::from_str::<IsoRegions>(&iso_text)
            .map(|iso| iso.regions)
            .unwrap_or_default();
        let iso_codes: HashSet<&str> =
            iso.iter().map(|region| region.code.as_str()).collect();
        let iso_by_name: HashMap<(String, String), &str> = iso
            .iter()
            .map(|region| {
                let country = region.code[..2].to_string();
                ((country, text.fold(&region.name)), region.code.as_str())
            })
            .collect();
        let fixes = &self.rules.region_fixes;
        let natural_earth = natural_earth_codes();
        tab_columns(&input_path("geonames_admin1"), |columns| {
            if columns.len() < 4 {
                return;
            }
            let key = columns[0].to_string();
            let (country, code) = key.split_once('.').unwrap_or((&key, ""));
            let direct = format!("{country}-{code}");
            let folded = text.fold(columns[1]);
            let candidates = [
                fixes.get(&key).cloned(),
                iso_codes.contains(direct.as_str()).then_some(direct),
                natural_earth.get(&key).cloned(),
                iso_by_name
                    .get(&(country.to_string(), folded.clone()))
                    .map(|code| code.to_string()),
            ];
            let iso = candidates
                .into_iter()
                .flatten()
                .find(|candidate| iso_codes.contains(candidate.as_str()));
            let region = Region {
                name: columns[1].to_string(),
                geonames_id: columns[3].trim().parse().unwrap_or(0),
                iso,
            };
            if let Some(iso) = &region.iso {
                self.region_by_iso.insert(iso.clone(), key.clone());
            }
            self.region_by_name.insert((country.to_string(), folded), key.clone());
            let ascii = text.fold(columns[2]);
            self.region_by_name
                .entry((country.to_string(), ascii))
                .or_insert(key.clone());
            self.regions.insert(key, region);
        });
        tab_columns(&input_path("geonames_admin2"), |columns| {
            if columns.len() < 2 {
                return;
            }
            self.districts.insert(columns[0].to_string(), columns[1].to_string());
        });
    }

    fn load_cities(&mut self, text: &Text) {
        tab_columns(&input_path("geonames_cities"), |columns| {
            if columns.len() < 19 {
                return;
            }
            let country = columns[8].to_string();
            let region_key = format!("{country}.{}", columns[10]);
            let district_key = format!("{region_key}.{}", columns[11]);
            let city = City {
                geonames_id: columns[0].parse().unwrap_or(0),
                name: columns[1].to_string(),
                ascii: columns[2].to_string(),
                lat: columns[4].parse().unwrap_or(0.0),
                lon: columns[5].parse().unwrap_or(0.0),
                region: self.regions.contains_key(&region_key).then_some(region_key),
                district: self
                    .districts
                    .contains_key(&district_key)
                    .then_some(district_key),
                country,
                population: columns[14].parse().unwrap_or(0),
                timezone: columns[17].to_string(),
            };
            let index = self.cities.len();
            let mut names: HashSet<String> =
                columns[3].split(',').map(|name| text.fold(name)).collect();
            names.insert(text.fold(&city.name));
            names.insert(text.fold(&city.ascii));
            for name in names.into_iter().filter(|name| !name.is_empty()) {
                self.names.entry((city.country.clone(), name)).or_default().push(index);
            }
            self.grid.entry(cell(city.lat, city.lon)).or_default().push(index);
            self.city_by_id.insert(city.geonames_id, index);
            self.cities.push(city);
        });
        let mut largest: HashMap<String, usize> = HashMap::new();
        for (index, city) in self.cities.iter().enumerate() {
            for key in
                [Some(city.country.clone()), city.region.clone()].into_iter().flatten()
            {
                let entry = largest.entry(key).or_insert(index);
                if self.cities[*entry].population < city.population {
                    *entry = index;
                }
            }
        }
        self.largest_city = largest;
    }

    fn load_postal(&mut self) {
        let mut grid: HashMap<(i32, i32), Vec<PostalEntry>> = HashMap::new();
        tab_columns(&input_path("geonames_postal"), |columns| {
            if columns.len() < 11 {
                return;
            }
            let (Ok(lat), Ok(lon)) =
                (columns[9].parse::<f64>(), columns[10].parse::<f64>())
            else {
                return;
            };
            let code = format!("{}\t{}", columns[0], columns[1]);
            grid.entry(cell(lat, lon)).or_default().push((code, lat, lon));
        });
        let radius = self.rules.postal_radius_km;
        for (index, city) in self.cities.iter().enumerate() {
            let (row, column) = cell(city.lat, city.lon);
            let mut nearby: Vec<(f64, &str)> = Vec::new();
            for cell_key in neighbours(row, column, 1) {
                for (code, lat, lon) in grid.get(&cell_key).into_iter().flatten() {
                    let (country, code) = code.split_once('\t').unwrap_or_default();
                    let distance = distance_km(city.lat, city.lon, *lat, *lon);
                    if country == city.country && distance <= radius {
                        nearby.push((distance, code));
                    }
                }
            }
            let Some(&(_, nearest)) = nearby.iter().min_by(|a, b| a.0.total_cmp(&b.0))
            else {
                continue;
            };
            self.postal.insert(index, nearest.to_string());
        }
    }

    pub fn city_by_geonames(&self, id: u32) -> Option<usize> {
        self.city_by_id.get(&id).copied()
    }

    pub fn region_by_iso(&self, iso: &str) -> Option<&str> {
        self.region_by_iso.get(iso).map(String::as_str)
    }

    pub fn region_by_name(&self, text: &Text, country: &str, name: &str) -> Option<&str> {
        let key = (country.to_string(), text.fold(name));
        self.region_by_name.get(&key).map(String::as_str)
    }

    pub fn nearest(
        &self,
        lat: f64,
        lon: f64,
        country: Option<&str>,
        max_km: f64,
    ) -> Option<(usize, f64)> {
        let (row, column) = cell(lat, lon);
        let rings = (max_km / 111.0).ceil() as i32 + 1;
        let mut best: Option<(usize, f64)> = None;
        for ring in 0..=rings {
            let stretch = (ring as f64 / lat.to_radians().cos().max(0.05)).ceil() as i32;
            for cell_key in ring_cells(row, column, ring, stretch.min(180)) {
                for &index in self.grid.get(&cell_key).into_iter().flatten() {
                    let city = &self.cities[index];
                    if country.is_some_and(|country| country != city.country) {
                        continue;
                    }
                    let distance = distance_km(lat, lon, city.lat, city.lon);
                    if distance <= max_km && best.is_none_or(|(_, best)| distance < best)
                    {
                        best = Some((index, distance));
                    }
                }
            }
            if best.is_some_and(|(_, distance)| {
                distance < (ring as f64 - 1.0).max(0.0) * 111.0
            }) {
                break;
            }
        }
        best
    }

    pub fn snap(&self, lat: f64, lon: f64, country: &str) -> Option<(usize, f64)> {
        let in_country = self
            .rules
            .snap_radii_km
            .iter()
            .find_map(|&radius| self.nearest(lat, lon, Some(country), radius));
        in_country.or_else(|| self.nearest(lat, lon, None, self.rules.snap_fallback_km))
    }

    pub fn city_by_name(
        &self,
        text: &Text,
        country: &str,
        region: Option<&str>,
        name: &str,
        near: Option<(f64, f64)>,
    ) -> Option<usize> {
        let folded = text.fold(name);
        if folded.is_empty() {
            return None;
        }
        let candidates = self.names.get(&(country.to_string(), folded))?;
        let in_region: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|&index| {
                region.is_some() && self.cities[index].region.as_deref() == region
            })
            .collect();
        let pool = if in_region.is_empty() { candidates.clone() } else { in_region };
        let Some((lat, lon)) = near else {
            return pool.into_iter().max_by_key(|&index| self.cities[index].population);
        };
        let distance = |index: &usize| {
            let city = &self.cities[*index];
            distance_km(lat, lon, city.lat, city.lon)
        };
        let closest =
            pool.into_iter().min_by(|a, b| distance(a).total_cmp(&distance(b)))?;
        (distance(&closest) <= self.rules.name_match_km).then_some(closest)
    }

    pub fn largest_city(&self, key: &str) -> Option<usize> {
        self.largest_city.get(key).copied()
    }
}

fn natural_earth_codes() -> HashMap<String, String> {
    let bytes = fs::read(input_path("naturalearth_admin1")).unwrap_or_default();
    let mut codes = HashMap::new();
    if bytes.len() < 32 {
        return codes;
    }
    let header_length = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
    let record_length = u16::from_le_bytes([bytes[10], bytes[11]]) as usize;
    let mut fields = Vec::new();
    let mut offset = 1;
    for descriptor in
        bytes[32..header_length].chunks(32).take_while(|chunk| chunk[0] != 0x0d)
    {
        let name_end = descriptor[..11].iter().position(|&byte| byte == 0).unwrap_or(11);
        let name = String::from_utf8_lossy(&descriptor[..name_end]).to_string();
        let length = descriptor[16] as usize;
        fields.push((name, offset, length));
        offset += length;
    }
    let field = |name: &str| fields.iter().find(|(field, _, _)| field == name).cloned();
    let (Some(iso), Some(gn)) = (field("iso_3166_2"), field("gn_a1_code")) else {
        return codes;
    };
    for record in bytes[header_length..].chunks(record_length) {
        if record.len() < record_length {
            break;
        }
        let read = |(_, offset, length): &(String, usize, usize)| {
            String::from_utf8_lossy(&record[*offset..offset + length]).trim().to_string()
        };
        let (iso, gn) = (read(&iso), read(&gn));
        if !gn.is_empty() && iso.len() > 3 && !iso.contains("~") {
            codes.insert(gn, iso);
        }
    }
    codes
}

fn neighbours(row: i32, column: i32, reach: i32) -> Vec<(i32, i32)> {
    let mut cells = Vec::new();
    for dr in -reach..=reach {
        for dc in -reach..=reach {
            cells.push((row + dr, column + dc));
        }
    }
    cells
}

fn ring_cells(row: i32, column: i32, ring: i32, stretch: i32) -> Vec<(i32, i32)> {
    let inner_stretch = if ring == 0 { -1 } else { ((ring - 1) * stretch) / ring.max(1) };
    let mut cells = Vec::new();
    for dr in -ring..=ring {
        for dc in -stretch..=stretch {
            if dr.abs() < ring && dc.abs() <= inner_stretch {
                continue;
            }
            let wrapped = (column + dc + 180).rem_euclid(360) - 180;
            cells.push((row + dr, wrapped));
        }
    }
    cells
}

#[derive(Clone, Copy, PartialEq)]
struct Vote {
    lat: f64,
    lon: f64,
    radius: f64,
    country: u16,
    region: Option<u32>,
    city: Option<u32>,
}

#[derive(Deserialize, Default)]
struct MmdbNames<'a> {
    #[serde(borrow, default)]
    en: Option<&'a str>,
}

#[derive(Deserialize, Default)]
struct MmdbArea<'a> {
    #[serde(default)]
    geoname_id: Option<u32>,
    #[serde(borrow, default)]
    iso_code: Option<&'a str>,
    #[serde(borrow, default)]
    names: MmdbNames<'a>,
}

#[derive(Deserialize, Default)]
struct MmdbLocation {
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    accuracy_radius: Option<u16>,
    #[serde(default)]
    metro_code: Option<u16>,
}

#[derive(Deserialize, Default)]
struct MmdbPlace<'a> {
    #[serde(borrow, default)]
    city: MmdbArea<'a>,
    #[serde(borrow, default)]
    country: MmdbArea<'a>,
    #[serde(borrow, default)]
    registered_country: MmdbArea<'a>,
    #[serde(default)]
    location: MmdbLocation,
    #[serde(borrow, default)]
    subdivisions: Vec<MmdbArea<'a>>,
}

pub fn walk_mmdb(
    path: &Path,
    mut visit: impl FnMut(usize, Address, Address, &maxminddb::LookupResult<'_, Vec<u8>>),
) {
    let Ok(reader) = Reader::open_readfile(path) else {
        log(&format!("{}: missing", path.display()));
        return;
    };
    let Ok(networks) = reader.networks(WithinOptions::default()) else {
        return;
    };
    for result in networks.flatten() {
        let Ok(network) = result.network() else {
            continue;
        };
        let (family, address) = from_ip(network.network());
        let length = u32::from(network.prefix());
        let ipv4_in_ipv6 = match network.network() {
            IpAddr::V6(v6) => u128::from(v6) <= u128::from(u32::MAX),
            IpAddr::V4(_) => false,
        };
        let (family, length) = match (family, network.network()) {
            (4, IpAddr::V6(_)) => continue,
            (6, _) if ipv4_in_ipv6 => (4, length.saturating_sub(96)),
            _ => (family, length),
        };
        let (first, last) = crate::spans::prefix_range(family, address, length);
        visit(family, first, last, &result);
    }
}

struct VoteSource {
    spans: Families<u32>,
    votes: Vec<Vote>,
}

impl VoteSource {
    fn new() -> VoteSource {
        VoteSource { spans: [Vec::new(), Vec::new()], votes: Vec::new() }
    }

    fn push(&mut self, family: usize, first: Address, last: Address, vote: Vote) {
        let reuse = self.votes.last().is_some_and(|previous| *previous == vote);
        if !reuse {
            self.votes.push(vote);
        }
        let id = self.votes.len() as u32 - 1;
        push_merged(&mut self.spans[slot(family)], first, last, id);
    }
}

pub fn resolve(geography: &Geography, text: &Text, geofeeds: &[GeofeedRow]) -> Places {
    let mut interner = Interner::default();
    let mut metro_mass: HashMap<(usize, u16), u128> = HashMap::new();
    let maxmind = maxmind_votes(geography, text, &mut interner, &mut metro_mass);
    let dbip = dbip_votes(geography, text, &mut interner);
    let count = |source: &VoteSource| source.spans[0].len() + source.spans[1].len();
    log(&format!("place votes: maxmind {} dbip {}", count(&maxmind), count(&dbip)));
    let sources = [&maxmind, &dbip];
    let mut exact: Families<u32> = [0, 1]
        .map(|family_slot| vote_family(geography, &mut interner, sources, family_slot));
    let geofeed_spans = geofeed_points(geography, text, geofeeds, &mut interner);
    for family_slot in 0..2 {
        let mut combined: Vec<Span<(u8, u32)>> = Vec::new();
        for span in &exact[family_slot] {
            combined.push(Span {
                first: span.first,
                last: span.last,
                value: (1, span.value),
            });
        }
        for span in &geofeed_spans[family_slot] {
            combined.push(Span {
                first: span.first,
                last: span.last,
                value: (0, span.value),
            });
        }
        let ranges: Vec<(Address, Address)> =
            combined.iter().map(|span| (span.first, span.last)).collect();
        let mut output = Vec::new();
        sweep(&ranges, |first, last, active| {
            let key = |index: &&usize| {
                let span = &combined[**index];
                (span.value.0, span.last - span.first)
            };
            let winner = active.iter().min_by_key(key).expect("active");
            push_merged(&mut output, first, last, combined[*winner].value.1);
        });
        exact[family_slot] = output;
    }
    let floors = accuracy_floors(
        &interner.points,
        &exact,
        geography.rules.accuracy_floor_percentile,
    );
    let mut floored = Interner {
        region_keys: interner.region_keys.clone(),
        country_codes: interner.country_codes.clone(),
        ..Interner::default()
    };
    for family in exact.iter_mut() {
        let mut output = Vec::new();
        for span in family.iter() {
            let mut point = interner.points[span.value as usize];
            point.accuracy = point.accuracy.max(floors[granularity(&point)]);
            push_merged(&mut output, span.first, span.last, floored.point(point));
        }
        *family = output;
    }
    let metros = majority_metros(metro_mass);
    Places {
        points: floored.points,
        exact,
        region_keys: floored.region_keys,
        country_codes: floored.country_codes,
        metros,
    }
}

fn vote_family(
    geography: &Geography,
    interner: &mut Interner,
    sources: [&VoteSource; 2],
    family_slot: usize,
) -> Vec<Span<u32>> {
    let layers = sources.map(|source| &source.spans[family_slot]);
    let mut leaders: Vec<(usize, Span<u32>)> =
        layers[0].iter().map(|span| (0, span.clone())).collect();
    leaders.extend(minus(layers[1], layers[0]).into_iter().map(|span| (1, span)));
    leaders.sort_by_key(|(_, span)| span.first);
    let mut cursors = [0usize; 2];
    let mut voted = Vec::new();
    for (leader, span) in leaders {
        let follower = 1 - leader;
        let cursor = &mut cursors[follower];
        let second = majority(layers[follower], cursor, span.first, span.last);
        let winner = sources[leader].votes[span.value as usize];
        let other = second.map(|vote| sources[follower].votes[vote as usize]);
        let point = match other.filter(|other| lends_city(&winner, other)) {
            Some(lender) => borrow_city(geography, &winner, &lender),
            None => decide(geography, &winner, other.as_ref()),
        };
        push_merged(&mut voted, span.first, span.last, interner.point(point));
    }
    voted
}

fn majority(
    spans: &[Span<u32>],
    cursor: &mut usize,
    first: Address,
    last: Address,
) -> Option<u32> {
    while *cursor < spans.len() && spans[*cursor].last < first {
        *cursor += 1;
    }
    let mut votes: Vec<(u32, Address)> = Vec::new();
    for span in spans[*cursor..].iter().take_while(|span| span.first <= last) {
        let mass = span.last.min(last) - span.first.max(first);
        match votes.iter_mut().find(|(value, _)| *value == span.value) {
            Some((_, total)) => *total += mass,
            None => votes.push((span.value, mass)),
        }
    }
    votes
        .into_iter()
        .max_by_key(|&(value, mass)| (mass, std::cmp::Reverse(value)))
        .map(|(value, _)| value)
}

fn minus<T: Clone, U>(spans: &[Span<T>], cover: &[Span<U>]) -> Vec<Span<T>> {
    let mut output = Vec::new();
    let mut cursor = 0;
    for span in spans {
        let mut start = span.first;
        while cursor < cover.len() && cover[cursor].last < start {
            cursor += 1;
        }
        let mut index = cursor;
        let mut finished = false;
        while let Some(hole) = cover.get(index).filter(|hole| hole.first <= span.last) {
            if hole.first > start {
                output.push(Span {
                    first: start,
                    last: hole.first - 1,
                    value: span.value.clone(),
                });
            }
            match hole.last.checked_add(1) {
                Some(next) if next <= span.last => start = next.max(start),
                _ => {
                    finished = true;
                    break;
                }
            }
            index += 1;
        }
        if !finished && start <= span.last {
            output.push(Span {
                first: start,
                last: span.last,
                value: span.value.clone(),
            });
        }
    }
    output
}

pub fn granularity(point: &Point) -> usize {
    match (point.city, point.region) {
        (Some(_), _) => 0,
        (None, Some(_)) => 1,
        _ => 2,
    }
}

fn accuracy_floors(
    points: &[Point],
    spans: &Families<u32>,
    percentile: usize,
) -> [u32; 3] {
    let mut accuracies: [Vec<u32>; 3] = Default::default();
    for span in spans.iter().flatten() {
        let point = &points[span.value as usize];
        accuracies[granularity(point)].push(point.accuracy);
    }
    accuracies.map(|mut values| {
        values.sort_unstable();
        let index = values.len() * percentile / 100;
        values.get(index.min(values.len().saturating_sub(1))).copied().unwrap_or(0)
    })
}

fn majority_metros(mass: HashMap<(usize, u16), u128>) -> HashMap<usize, u16> {
    let mut best: HashMap<usize, (u128, u16)> = HashMap::new();
    for ((city, metro), weight) in mass {
        let entry = best.entry(city).or_insert((0, metro));
        if weight > entry.0 || (weight == entry.0 && metro < entry.1) {
            *entry = (weight, metro);
        }
    }
    best.into_iter().map(|(city, (_, metro))| (city, metro)).collect()
}

fn vote_city<'a>(geography: &'a Geography, vote: &Vote) -> Option<&'a City> {
    vote.city.map(|city| &geography.cities[city as usize])
}

fn decide(geography: &Geography, winner: &Vote, other: Option<&Vote>) -> Point {
    Point {
        lat: (winner.lat * 1e4).round() as i32,
        lon: (winner.lon * 1e4).round() as i32,
        accuracy: winner.radius.round() as u32,
        country: winner.country,
        region: winner.region,
        city: winner.city,
        confidence: confidence(geography, winner, other),
    }
}

fn lends_city(winner: &Vote, other: &Vote) -> bool {
    let region_agrees = winner.region.is_none() || winner.region == other.region;
    winner.city.is_none()
        && other.city.is_some()
        && winner.country == other.country
        && region_agrees
}

fn borrow_city(geography: &Geography, winner: &Vote, lender: &Vote) -> Point {
    Point {
        lat: (lender.lat * 1e4).round() as i32,
        lon: (lender.lon * 1e4).round() as i32,
        accuracy: winner.radius.max(lender.radius).round() as u32,
        country: winner.country,
        region: lender.region,
        city: lender.city,
        confidence: geography.rules.confidence.borrowed_city,
    }
}

fn confidence(geography: &Geography, winner: &Vote, other: Option<&Vote>) -> u32 {
    let rules = &geography.rules.confidence;
    let Some(other) = other else {
        let region_or_better = winner.city.is_some() || winner.region.is_some();
        return if region_or_better {
            rules.single_source_region
        } else {
            rules.single_source_country
        };
    };
    match (vote_city(geography, winner), vote_city(geography, other)) {
        (Some(_), Some(_)) if winner.city == other.city => rules.same_city,
        (Some(a), Some(b)) => {
            let distance = distance_km(a.lat, a.lon, b.lat, b.lon);
            let tier = rules.distance_km.iter().find(|(limit, _)| distance <= *limit);
            tier.map_or(rules.farther, |(_, confidence)| *confidence)
        }
        _ if winner.country == other.country => rules.country_agrees,
        _ => rules.country_disagrees,
    }
}

fn make_vote(
    geography: &Geography,
    interner: &mut Interner,
    country: &str,
    region: Option<&str>,
    city: Option<usize>,
    coordinates: (f64, f64),
    radius: f64,
) -> Vote {
    let city_index = city.filter(|&index| geography.cities[index].country == country);
    let (lat, lon, radius) = match city_index {
        Some(index) => {
            let city = &geography.cities[index];
            let distance = distance_km(coordinates.0, coordinates.1, city.lat, city.lon);
            (city.lat, city.lon, radius.max(distance))
        }
        None => (coordinates.0, coordinates.1, radius),
    };
    let region = city_index
        .and_then(|index| geography.cities[index].region.as_deref())
        .or(region)
        .map(|key| interner.region(key));
    Vote {
        lat,
        lon,
        radius,
        country: interner.country(country),
        region,
        city: city_index.map(|index| index as u32),
    }
}

fn locate(
    geography: &Geography,
    text: &Text,
    country: &str,
    region: Option<&str>,
    name: Option<&str>,
    coordinates: (f64, f64),
    snap_cache: &mut HashMap<(i64, i64, String), Option<usize>>,
) -> Option<usize> {
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        let found =
            geography.city_by_name(text, country, region, name, Some(coordinates));
        if found.is_some() {
            return found;
        }
    }
    name.filter(|name| !name.is_empty())?;
    let key =
        ((coordinates.0 * 1e4) as i64, (coordinates.1 * 1e4) as i64, country.to_string());
    *snap_cache.entry(key).or_insert_with(|| {
        let (index, _) = geography.snap(coordinates.0, coordinates.1, country)?;
        (geography.cities[index].country == country).then_some(index)
    })
}

fn maxmind_votes(
    geography: &Geography,
    text: &Text,
    interner: &mut Interner,
    metro_mass: &mut HashMap<(usize, u16), u128>,
) -> VoteSource {
    let mut source = VoteSource::new();
    let mut cache = HashMap::new();
    walk_mmdb(&input_path("geolite2_city"), |family, first, last, result| {
        let Ok(Some(place)) = result.decode::<MmdbPlace>() else {
            return;
        };
        let country_area = if place.country.iso_code.is_some() {
            &place.country
        } else {
            &place.registered_country
        };
        let Some(country) = country_area.iso_code else {
            return;
        };
        let (Some(lat), Some(lon)) = (place.location.latitude, place.location.longitude)
        else {
            return;
        };
        if lat == 0.0 && lon == 0.0 {
            return;
        }
        let region = place
            .subdivisions
            .first()
            .and_then(|area| area.iso_code)
            .and_then(|code| geography.region_by_iso(&format!("{country}-{code}")));
        let country_only = place.country.iso_code.is_none();
        let city =
            place.city.geoname_id.and_then(|id| geography.city_by_geonames(id)).or_else(
                || {
                    let name = place.city.names.en?;
                    locate(
                        geography,
                        text,
                        country,
                        region,
                        Some(name),
                        (lat, lon),
                        &mut cache,
                    )
                },
            );
        let city = city.filter(|_| !country_only);
        let region = region.filter(|_| !country_only);
        let radius = f64::from(place.location.accuracy_radius.unwrap_or(0));
        let vote =
            make_vote(geography, interner, country, region, city, (lat, lon), radius);
        if let (Some(city), Some(metro)) = (city, place.location.metro_code) {
            *metro_mass.entry((city, metro)).or_default() += last - first + 1;
        }
        source.push(family, first, last, vote);
    });
    source
}

fn dbip_votes(geography: &Geography, text: &Text, interner: &mut Interner) -> VoteSource {
    let mut source = VoteSource::new();
    let mut cache = HashMap::new();
    walk_mmdb(&input_path("dbip_city"), |family, first, last, result| {
        let Ok(Some(place)) = result.decode::<MmdbPlace>() else {
            return;
        };
        let (Some(country), Some(lat), Some(lon)) =
            (place.country.iso_code, place.location.latitude, place.location.longitude)
        else {
            return;
        };
        let region_name = place.subdivisions.first().and_then(|area| area.names.en);
        let region =
            region_name.and_then(|name| geography.region_by_name(text, country, name));
        let name = place.city.names.en;
        let city = locate(geography, text, country, region, name, (lat, lon), &mut cache);
        let vote = make_vote(geography, interner, country, region, city, (lat, lon), 0.0);
        source.push(family, first, last, vote);
    });
    source
}

#[derive(Clone)]
pub struct GeofeedRow {
    pub family: usize,
    pub first: Address,
    pub last: Address,
    pub country: String,
    pub region: String,
    pub city: String,
}

fn geofeed_points(
    geography: &Geography,
    text: &Text,
    rows: &[GeofeedRow],
    interner: &mut Interner,
) -> Families<u32> {
    let mut spans: [Vec<Span<u32>>; 2] = [Vec::new(), Vec::new()];
    for row in rows {
        let Some(city_or_region) = place_geofeed_row(geography, text, row) else {
            continue;
        };
        let (city, region) = city_or_region;
        let anchor =
            city.or_else(|| geography.largest_city(region.unwrap_or(&row.country)));
        let Some(anchor) = anchor.map(|index| &geography.cities[index]) else {
            continue;
        };
        let point = Point {
            lat: (anchor.lat * 1e4).round() as i32,
            lon: (anchor.lon * 1e4).round() as i32,
            accuracy: 0,
            country: interner.country(&row.country),
            region: region.map(|key| interner.region(key)),
            city: city.map(|index| index as u32),
            confidence: geography.rules.geofeed_confidence,
        };
        let id = interner.point(point);
        spans[slot(row.family)].push(Span {
            first: row.first,
            last: row.last,
            value: id,
        });
    }
    spans.map(|mut family| {
        family.sort_by_key(|span| (span.first, std::cmp::Reverse(span.last)));
        narrowest(&family)
    })
}

pub fn place_geofeed_row<'a>(
    geography: &'a Geography,
    text: &Text,
    row: &GeofeedRow,
) -> Option<(Option<usize>, Option<&'a str>)> {
    if !geography.countries.contains_key(&row.country) {
        return None;
    }
    let region = geography.region_by_iso(&row.region);
    let city = geography.city_by_name(text, &row.country, region, &row.city, None);
    let region =
        city.and_then(|index| geography.cities[index].region.as_deref()).or(region);
    Some((city, region))
}

fn merged_intervals(
    mut ranges: Vec<(usize, Address, Address)>,
) -> Vec<(usize, Address, Address)> {
    ranges.sort_unstable();
    let mut merged: Vec<(usize, Address, Address)> = Vec::new();
    for (family, first, last) in ranges {
        match merged.last_mut() {
            Some(previous)
                if previous.0 == family && first <= previous.2.saturating_add(1) =>
            {
                previous.2 = previous.2.max(last);
            }
            _ => merged.push((family, first, last)),
        }
    }
    merged
}

fn vouched(allowed: &[(usize, Address, Address)], row: &GeofeedRow) -> bool {
    let index = allowed.partition_point(|&(family, first, _)| {
        (family, first) <= (row.family, row.first)
    });
    index > 0 && {
        let (family, _, last) = allowed[index - 1];
        family == row.family && last >= row.last
    }
}

pub fn collect_geofeeds(
    claims: &crate::feeds::Claims,
    networks: &crate::network::Networks,
) -> Vec<GeofeedRow> {
    let mut rows = claims.geofeed_rows.clone();
    let mut by_url: BTreeMap<&str, AllowedRanges> = BTreeMap::new();
    for reference in &networks.whois_geofeeds {
        let (ranges, orgs) = by_url.entry(reference.url.as_str()).or_default();
        ranges.push((reference.family, reference.first, reference.last));
        orgs.extend(reference.org.as_deref());
    }
    let (mut accepted, mut rejected) = (0usize, 0usize);
    for (url, (mut allowed, orgs)) in by_url {
        for org in orgs {
            allowed.extend(networks.org_ranges.get(org).into_iter().flatten().copied());
        }
        let allowed = merged_intervals(allowed);
        let bytes = fs::read(crate::fetch::geofeed_file(url)).unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        for row in crate::feeds::parse_geofeed(&text) {
            if vouched(&allowed, &row) {
                accepted += 1;
                rows.push(row);
            } else {
                rejected += 1;
            }
        }
    }
    log(&format!(
        "geofeeds: {} published rows, {accepted} vouched whois rows, {rejected} rejected",
        claims.geofeed_rows.len()
    ));
    rows
}
