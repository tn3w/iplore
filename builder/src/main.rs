mod abuse;
mod assemble;
mod feeds;
mod fetch;
mod geo;
mod mmdb;
mod network;
mod rdns;
mod spans;
mod template;
mod text;
mod whois;
mod write;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::time::Instant;

use crate::spans::{lookup, slot};

pub type Environment = HashMap<String, String>;

pub fn log(message: &str) {
    eprintln!("{message}");
}

pub fn load_json<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = format!("data/{name}");
    let text =
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn load_environment() -> Environment {
    let mut environment: Environment = std::env::vars().collect();
    let text = fs::read_to_string(".env").unwrap_or_default();
    for line in text.lines().filter(|line| !line.trim_start().starts_with('#')) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').trim_matches('\'');
        environment.entry(key.trim().to_string()).or_insert(value.to_string());
    }
    environment.retain(|_, value| !value.is_empty());
    environment
}

struct Inputs {
    text: text::Text,
    geography: geo::Geography,
    claims: feeds::Claims,
    networks: network::Networks,
    geofeeds: Vec<geo::GeofeedRow>,
}

fn load_inputs() -> Inputs {
    let started = Instant::now();
    let text = text::Text::load();
    let (geography, claims) =
        rayon::join(|| geo::Geography::load(&text), || feeds::load(&text));
    log(&format!("loaded geography and feeds in {:.1?}", started.elapsed()));
    let networks = network::build(&text, &claims);
    log(&format!("networks ready after {:.1?}", started.elapsed()));
    let geofeeds = geo::collect_geofeeds(&claims, &networks);
    Inputs { text, geography, claims, networks, geofeeds }
}

fn build(selections: &[String]) -> io::Result<()> {
    let started = Instant::now();
    let inputs = load_inputs();
    let places = geo::resolve(&inputs.geography, &inputs.text, &inputs.geofeeds);
    log(&format!("places ready after {:.1?}", started.elapsed()));
    let schema = write::Schema::load();
    let abuse =
        abuse::build(&inputs.claims, &inputs.networks, &inputs.text, schema.flag_names());
    log(&format!("abuse ready after {:.1?}", started.elapsed()));
    let dataset =
        assemble::assemble(&inputs.geography, &places, &inputs.networks, &abuse, &schema);
    fs::create_dir_all("dist")?;
    for selection in selections {
        if selection == "blocklist" {
            write::write_blocklist(&dataset, "dist/blocklist.netset")?;
            continue;
        }
        write::write(
            &dataset,
            &schema,
            selection,
            &format!("dist/iplore-{selection}.ipl"),
        )?;
    }
    let silent = inputs.claims.silent();
    log(&format!("silent feeds ({}): {}", silent.len(), silent.join(", ")));
    log(&format!("build finished in {:.1?}", started.elapsed()));
    Ok(())
}

fn benchmark_places() -> io::Result<()> {
    let inputs = load_inputs();
    let every = inputs.geography.rules.holdout_every;
    let (held, kept): (Vec<_>, Vec<_>) = inputs
        .geofeeds
        .iter()
        .cloned()
        .enumerate()
        .partition(|(index, _)| index % every == 0);
    let kept: Vec<geo::GeofeedRow> = kept.into_iter().map(|(_, row)| row).collect();
    let places = geo::resolve(&inputs.geography, &inputs.text, &kept);
    let mut tallies: [PlaceTally; 2] = Default::default();
    for (_, row) in held {
        let expected = geo::place_geofeed_row(&inputs.geography, &inputs.text, &row);
        let Some(expected) = expected.and_then(|(city, _)| city) else {
            continue;
        };
        let family_slot = slot(row.family);
        let tally = &mut tallies[family_slot];
        tally.total += 1;
        let Some(&point) = lookup(&places.exact[family_slot], row.first) else {
            continue;
        };
        let point = &places.points[point as usize];
        let city = &inputs.geography.cities[expected];
        let (lat, lon) = (f64::from(point.lat) / 1e4, f64::from(point.lon) / 1e4);
        let error = geo::distance_km(lat, lon, city.lat, city.lon);
        tally.answered += 1;
        tally.cities += usize::from(point.city == Some(expected as u32));
        tally.countries +=
            usize::from(places.country_codes[point.country as usize] == city.country);
        tally.covered += usize::from(error <= f64::from(point.accuracy));
        tally.errors.push(error);
    }
    for (family, tally) in [4, 6].iter().zip(tallies) {
        tally.report(*family);
    }
    Ok(())
}

#[derive(Default)]
struct PlaceTally {
    total: usize,
    answered: usize,
    cities: usize,
    countries: usize,
    covered: usize,
    errors: Vec<f64>,
}

impl PlaceTally {
    fn report(mut self, family: u8) {
        let share = |count: usize| count as f64 * 100.0 / self.total.max(1) as f64;
        self.errors.sort_by(f64::total_cmp);
        let percentile = |rank: usize| {
            let index =
                (self.errors.len() * rank / 100).min(self.errors.len().max(1) - 1);
            self.errors.get(index).copied().unwrap_or(0.0)
        };
        log(&format!(
            "held-out geofeed rows v{family}: {}/{} answered, city {:.1}%, \
             country {:.2}%, within accuracy {:.1}%, \
             error km p50 {:.0} p90 {:.0} p99 {:.0}",
            self.answered,
            self.total,
            share(self.cities),
            share(self.countries),
            share(self.covered),
            percentile(50),
            percentile(90),
            percentile(99),
        ));
    }
}

fn benchmark_categories() -> io::Result<()> {
    let inputs = load_inputs();
    let networks = &inputs.networks;
    let text = &inputs.text;
    let mut tallies: HashMap<String, [usize; 2]> = HashMap::new();
    for (asn, listed) in &networks.list_categories {
        let row = &networks.rows[networks.asn_rows[asn] as usize];
        let operator = &row.operator;
        let categories = &networks.rules.categories;
        let mailbox = operator.abuse_email.as_deref();
        let rules = [
            (
                "domain",
                network::domain_category(
                    operator.website.as_deref(),
                    mailbox,
                    categories,
                ),
            ),
            ("name", network::keyword_category(&row.names, categories, text)),
            ("users", network::users_category(row, categories, text)),
            ("netnames", networks.netname_coverage.get(asn).cloned()),
        ];
        for (rule, said) in rules {
            let Some(said) = said else {
                continue;
            };
            let tally = tallies.entry(format!("{rule}:{said}")).or_default();
            tally[0] += 1;
            if &said == listed {
                tally[1] += 1;
            }
        }
    }
    let mut rows: Vec<_> = tallies.into_iter().collect();
    rows.sort();
    for (rule, [total, agreeing]) in rows {
        let share = agreeing as f64 * 100.0 / total.max(1) as f64;
        log(&format!("{rule:<28} {agreeing:>6}/{total:<6} {share:.1}% agree with lists"));
    }
    Ok(())
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let environment = load_environment();
    let usage = "usage: builder fetch | rdns | licenses | bench-place | bench-category \
                 | check <a> <b> | <selection>... (full, blocklist, place+metro, ...)";
    let result = match arguments.first().map(String::as_str) {
        Some("fetch") => fetch::run(&environment),
        Some("rdns") => rdns::run(),
        Some("bench-place") => benchmark_places(),
        Some("bench-category") => benchmark_categories(),
        Some("licenses") => write::write_licenses("data/LICENSES"),
        Some("check") if arguments.len() == 3 => {
            check_union(&arguments[1], &arguments[2])
        }
        Some(_) => build(&arguments),
        None => Err(io::Error::other(usage)),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn flatten(
    prefix: &str,
    value: &serde_json::Value,
    output: &mut HashMap<String, String>,
) {
    let serde_json::Value::Object(map) = value else {
        output.insert(prefix.to_string(), value.to_string());
        return;
    };
    for (key, child) in map {
        let name =
            if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
        flatten(&name, child, output);
    }
}

fn field_names(reader: &reader::Reader) -> Vec<String> {
    let fields = reader.about()["fields"].as_array().cloned().unwrap_or_default();
    fields.iter().filter_map(|field| field["name"].as_str().map(str::to_string)).collect()
}

fn check_union(left: &str, right: &str) -> io::Result<()> {
    let (left, right) = (reader::Reader::open(left)?, reader::Reader::open(right)?);
    let right_fields = field_names(&right);
    let common: Vec<String> = field_names(&left)
        .into_iter()
        .filter(|field| right_fields.contains(field) && field != "place.time")
        .collect();
    let mut mismatches: HashMap<String, usize> = HashMap::new();
    let mut state = 0x9e3779b97f4a7c15u64;
    let samples = 100_000;
    for _ in 0..samples {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let address = std::net::Ipv4Addr::from(state as u32).to_string();
        let mut answers = [HashMap::new(), HashMap::new()];
        for (reader, answer) in [&left, &right].into_iter().zip(answers.iter_mut()) {
            flatten("", &reader.lookup_json(&address).unwrap_or_default(), answer);
        }
        for field in
            common.iter().filter(|field| answers[0].get(*field) != answers[1].get(*field))
        {
            *mismatches.entry(field.clone()).or_default() += 1;
        }
    }
    log(&format!("{} common fields, {samples} random addresses", common.len()));
    for (field, count) in &mismatches {
        log(&format!("  mismatch {field}: {count}"));
    }
    log(&format!("fields with mismatches: {}", mismatches.len()));
    Ok(())
}
