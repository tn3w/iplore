use std::collections::HashMap;
use std::fs;

use rayon::prelude::*;
use regex::Regex;
use serde::Deserialize;

use crate::fetch::input_path;
use crate::geo::GeofeedRow;
use crate::spans::{Address, Families, Span, parse_range, prefix_range, slot};
use crate::text::{Patterns, Text, decode_line};
use crate::{load_json, log};

#[derive(Deserialize, Clone, Default)]
#[serde(default)]
pub struct Feed {
    pub name: String,
    pub regex: Option<String>,
    pub format: Option<String>,
    pub scope: Option<String>,
    pub provider: Option<String>,
    pub user: Option<String>,
    pub service: Option<String>,
    pub evidence: Option<String>,
    pub threat: Option<String>,
    pub window: Option<u32>,
    pub quality: Option<String>,
    pub group: Option<String>,
    pub flags: Vec<String>,
    pub weak: bool,
    pub trusted: bool,
    pub suffix: Option<u32>,
    pub geofeed: bool,
}

#[derive(Clone, PartialEq, Eq, Hash, Default, Debug)]
pub struct Meaning {
    pub feed: String,
    pub provider: Option<String>,
    pub user: Option<String>,
    pub service: Option<String>,
    pub evidence: Option<String>,
    pub threat: Option<String>,
    pub risk: u32,
    pub quality: u32,
    pub group: String,
    pub window: Option<u32>,
    pub flags: Vec<String>,
    pub weak: bool,
    pub trusted: bool,
}

#[derive(Default)]
pub struct Claims {
    pub meanings: Vec<Meaning>,
    meaning_ids: HashMap<Meaning, u32>,
    pub ranges: Families<u32>,
    pub asns: Vec<(u32, u32)>,
    pub matches: Vec<(String, usize)>,
    pub geofeed_rows: Vec<GeofeedRow>,
}

#[derive(Deserialize)]
pub struct Ratings {
    threat_risk: HashMap<String, f64>,
    freshness: Vec<(u32, f64)>,
    default_window: u32,
    quality: HashMap<String, f64>,
    default_quality: String,
}

impl Ratings {
    pub fn quality(&self, name: Option<&str>) -> f64 {
        let name = name.unwrap_or(&self.default_quality);
        self.quality
            .get(name)
            .copied()
            .unwrap_or_else(|| panic!("unknown quality {name}"))
    }

    pub fn risk(&self, threat: Option<&str>, window: Option<u32>, quality: f64) -> f64 {
        let Some(base) = threat.map(|threat| self.threat_risk[threat]) else {
            return 0.0;
        };
        let window = window.unwrap_or(self.default_window);
        let fresh = self.freshness.iter().find(|(days, _)| window <= *days);
        let fresh = fresh.or(self.freshness.last()).map_or(1.0, |(_, factor)| *factor);
        base * fresh * quality
    }
}

#[derive(Deserialize)]
struct IpsumRules {
    quality_by_count: Vec<(u32, f64)>,
}

#[derive(Deserialize)]
struct ScoringFeeds {
    #[serde(flatten)]
    ratings: Ratings,
    widest_feed_prefix: HashMap<String, u32>,
    ipsum: IpsumRules,
}

pub fn per_mille(value: f64) -> u32 {
    (value * 1000.0).round() as u32
}

fn vocabulary_threat(threat: Option<&String>, ratings: &Ratings) -> Option<String> {
    threat
        .filter(|threat| ratings.threat_risk.contains_key(*threat) && *threat != "abuse")
        .cloned()
}

impl Feed {
    fn meaning(&self, ratings: &Ratings) -> Meaning {
        let quality = ratings.quality(self.quality.as_deref());
        Meaning {
            feed: self.name.clone(),
            provider: self.provider.clone(),
            user: self.user.clone(),
            service: self.service.clone(),
            evidence: self.evidence.clone(),
            threat: vocabulary_threat(self.threat.as_ref(), ratings),
            risk: per_mille(ratings.risk(self.threat.as_deref(), self.window, quality)),
            quality: per_mille(quality),
            group: self.group.clone().unwrap_or_else(|| self.name.clone()),
            window: self.window,
            flags: self.flags.clone(),
            weak: self.weak,
            trusted: self.trusted,
        }
    }
}

#[derive(Default)]
struct Parsed {
    meanings: Vec<Meaning>,
    meaning_ids: HashMap<Meaning, u32>,
    ranges: Vec<(usize, Address, Address, u32)>,
    asns: Vec<(u32, u32)>,
    geofeed_rows: Vec<GeofeedRow>,
}

impl Parsed {
    fn local(&mut self, meaning: &Meaning) -> u32 {
        if let Some(&id) = self.meaning_ids.get(meaning) {
            return id;
        }
        self.meanings.push(meaning.clone());
        let id = self.meanings.len() as u32 - 1;
        self.meaning_ids.insert(meaning.clone(), id);
        id
    }

    fn range(&mut self, family: usize, first: Address, last: Address, meaning: &Meaning) {
        let id = self.local(meaning);
        self.ranges.push((family, first, last, id));
    }

    fn count(&self) -> usize {
        self.ranges.len() + self.asns.len()
    }
}

impl Claims {
    fn meaning_id(&mut self, meaning: Meaning) -> u32 {
        if let Some(&id) = self.meaning_ids.get(&meaning) {
            return id;
        }
        self.meanings.push(meaning.clone());
        let id = self.meanings.len() as u32 - 1;
        self.meaning_ids.insert(meaning, id);
        id
    }

    fn absorb(&mut self, name: &str, parsed: Parsed) {
        self.matches.push((name.to_string(), parsed.count()));
        let global: Vec<u32> =
            parsed.meanings.into_iter().map(|meaning| self.meaning_id(meaning)).collect();
        for (family, first, last, local) in parsed.ranges {
            let value = global[local as usize];
            self.ranges[slot(family)].push(Span { first, last, value });
        }
        for (asn, local) in parsed.asns {
            self.asns.push((asn, global[local as usize]));
        }
        self.geofeed_rows.extend(parsed.geofeed_rows);
    }

    pub fn silent(&self) -> Vec<&str> {
        let silent = self.matches.iter().filter(|(_, count)| *count == 0);
        silent.map(|(name, _)| name.as_str()).collect()
    }
}

pub fn load(text: &Text) -> Claims {
    let feeds: Vec<Feed> = load_json("feeds.json");
    let scoring: ScoringFeeds = load_json("scoring.json");
    let patterns = &text.patterns();
    let parsed: Vec<(String, Parsed)> = feeds
        .par_iter()
        .map(|feed| (feed.name.clone(), parse_feed(feed, &scoring, patterns)))
        .collect();
    let mut claims = Claims::default();
    for (name, parsed) in parsed {
        claims.absorb(&name, parsed);
    }
    let total: usize = claims.matches.iter().map(|(_, count)| count).sum();
    log(&format!("feeds: {} feeds, {total} matches", claims.matches.len()));
    for (name, count) in &claims.matches {
        log(&format!("  feed {name:<32} {count:>9}"));
    }
    claims
}

fn read_feed(name: &str) -> String {
    let path = input_path(&format!("feeds/{name}"));
    let mut bytes = fs::read(&path).unwrap_or_default();
    if let Ok(resolved) = fs::read(path.with_extension("resolved")) {
        bytes.push(b'\n');
        bytes.extend(resolved);
    }
    bytes.split(|&byte| byte == b'\n').map(decode_line).collect::<Vec<_>>().join("\n")
}

fn parse_feed(feed: &Feed, scoring: &ScoringFeeds, patterns: &Patterns) -> Parsed {
    let text = read_feed(&feed.name);
    let mut parsed = Parsed::default();
    let meaning = feed.meaning(&scoring.ratings);
    if feed.scope.as_deref() == Some("asn") {
        let pattern = feed.regex.as_ref().map(|pattern| format!("(?m){pattern}"));
        let pattern =
            Regex::new(pattern.as_deref().unwrap_or(&patterns.asn)).expect("asn regex");
        let id = parsed.local(&meaning);
        for captures in pattern.captures_iter(&text) {
            if let Some(asn) = captures.get(1).and_then(|asn| asn.as_str().parse().ok()) {
                parsed.asns.push((asn, id));
            }
        }
        return parsed;
    }
    if feed.format.as_deref() == Some("ipsum") {
        return parse_ipsum(&text, feed, &meaning, scoring);
    }
    if feed.geofeed {
        parsed.geofeed_rows = parse_geofeed(&text);
    }
    let custom =
        feed.regex.as_deref().map(|pattern| Regex::new(&format!("(?m){pattern}")));
    let custom = custom.transpose().expect("feed regex");
    let default = Regex::new(&patterns.address).expect("address regex");
    let tokens: Vec<&str> = match &custom {
        Some(pattern) => pattern
            .captures_iter(&text)
            .filter_map(|captures| captures.get(1).map(|token| token.as_str()))
            .collect(),
        None => default.find_iter(&text).map(|token| token.as_str()).collect(),
    };
    for token in tokens {
        let Some((family, mut first, mut last)) = parse_range(token) else {
            continue;
        };
        if let Some(suffix) = feed.suffix.filter(|_| family == 4) {
            (first, last) = prefix_range(family, first, suffix);
        }
        let widest = scoring.widest_feed_prefix[&family.to_string()];
        if prefix_range(family, first, widest).1 < last {
            continue;
        }
        parsed.range(family, first, last, &meaning);
    }
    parsed
}

pub fn parse_geofeed(text: &str) -> Vec<GeofeedRow> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let columns: Vec<&str> = line.split(',').map(str::trim).collect();
        if columns.len() < 4 {
            continue;
        }
        let Some((family, first, last)) = parse_range(columns[0]) else {
            continue;
        };
        let country = columns[1].to_uppercase();
        if country.len() != 2 {
            continue;
        }
        rows.push(GeofeedRow {
            family,
            first,
            last,
            country,
            region: columns[2].to_uppercase(),
            city: columns[3].to_string(),
        });
    }
    rows
}

fn parse_ipsum(
    text: &str,
    feed: &Feed,
    meaning: &Meaning,
    scoring: &ScoringFeeds,
) -> Parsed {
    let rules = &scoring.ipsum;
    let mut parsed = Parsed::default();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let mut columns = line.split_whitespace();
        let (Some(address), Some(count)) = (columns.next(), columns.next()) else {
            continue;
        };
        let Some((family, first, last)) = parse_range(address) else {
            continue;
        };
        let count: u32 = count.parse().unwrap_or(0);
        let table = rules.quality_by_count.iter().rev();
        let quality = table
            .clone()
            .find(|(minimum, _)| count >= *minimum)
            .map_or(0.0, |entry| entry.1);
        let mut meaning = meaning.clone();
        let risk = scoring.ratings.risk(feed.threat.as_deref(), feed.window, quality);
        meaning.risk = per_mille(risk);
        meaning.quality = per_mille(quality);
        parsed.range(family, first, last, &meaning);
    }
    parsed
}
