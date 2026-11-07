use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Deserialize;

use crate::feeds::{Claims, Meaning, per_mille};
use crate::network::Networks;
use crate::spans::{Address, Families, Span, push_merged, sweep};
use crate::text::Text;
use crate::{load_json, log};

#[derive(Deserialize)]
struct Trusted {
    damping: f64,
    accepted_evidence: Vec<String>,
}

#[derive(Deserialize)]
struct NetworkRating {
    v6_unit_bits: u32,
    minimum: f64,
}

#[derive(Deserialize)]
struct BlocklistRules {
    minimum_risk: f64,
}

#[derive(Deserialize)]
struct Inference {
    evidence: String,
    services: BTreeMap<String, Vec<String>>,
    flags: BTreeMap<String, Vec<String>>,
    flag_asns: BTreeMap<String, Vec<u32>>,
}

#[derive(Deserialize)]
struct Scoring {
    freshness: Vec<(u32, f64)>,
    service_risk: HashMap<String, f64>,
    evidence_weight: HashMap<String, f64>,
    service_order: Vec<String>,
    trusted: Trusted,
    network: NetworkRating,
    risk_cap: f64,
    blocklist: BlocklistRules,
    inference: Inference,
}

#[derive(Clone, PartialEq, Eq, Hash, Default, Debug)]
pub struct Record {
    pub risk: Option<u32>,
    pub threat: Option<String>,
    pub reports: Option<u32>,
    pub last_seen_days: Option<u32>,
    pub service: Option<String>,
    pub evidence: Option<String>,
    pub provider: Option<String>,
    pub user_type: Option<String>,
    pub flags: u64,
}

pub struct Abuse {
    pub records: Vec<Record>,
    pub spans: Families<u32>,
    pub hosts: [Vec<(Address, u32)>; 2],
    pub network_risk: HashMap<u32, u32>,
    pub blocklist: Families<()>,
}

#[derive(Default)]
struct Interner {
    records: Vec<Record>,
    ids: HashMap<Record, u32>,
}

impl Interner {
    fn id(&mut self, record: Record) -> Option<u32> {
        if record == Record::default() {
            return None;
        }
        if let Some(&id) = self.ids.get(&record) {
            return Some(id);
        }
        self.records.push(record.clone());
        self.ids.insert(record, self.records.len() as u32 - 1);
        Some(self.records.len() as u32 - 1)
    }
}

#[derive(Clone, Copy)]
struct Active<'a> {
    meaning: &'a Meaning,
    size: Address,
    baseline: bool,
}

struct Rater<'a> {
    scoring: &'a Scoring,
    flags: Vec<String>,
}

impl Rater<'_> {
    fn strength(&self, claim: &Active) -> (bool, u32, usize, bool) {
        let order = &self.scoring.service_order;
        let meaning = claim.meaning;
        let evidence = meaning.evidence.as_ref();
        let weight = evidence.and_then(|e| self.scoring.evidence_weight.get(e)).copied();
        let doubt = per_mille(1.0 - weight.unwrap_or(0.0));
        let service = meaning.service.as_ref();
        let rank =
            service.and_then(|service| order.iter().position(|item| item == service));
        (meaning.weak, doubt, rank.unwrap_or(order.len()), claim.baseline)
    }

    fn accepted(&self, claim: &Active, trusted: bool) -> bool {
        let accepted = &self.scoring.trusted.accepted_evidence;
        !trusted || claim.meaning.evidence.as_ref().is_none_or(|e| accepted.contains(e))
    }

    fn service_floor(&self, claim: &Active) -> f64 {
        let meaning = claim.meaning;
        let worth =
            meaning.service.as_ref().and_then(|s| self.scoring.service_risk.get(s));
        let evidence = meaning.evidence.as_ref();
        let weight = evidence.and_then(|e| self.scoring.evidence_weight.get(e));
        let quality = f64::from(meaning.quality) / 1000.0;
        worth.copied().unwrap_or(0.0) * weight.copied().unwrap_or(0.0) * quality
    }

    fn snap_days(&self, window: u32) -> u32 {
        let days = self.scoring.freshness.iter().map(|(days, _)| *days);
        let last = self.scoring.freshness.last().map_or(window, |(days, _)| *days);
        days.clone().find(|&days| days >= window).unwrap_or(last)
    }

    fn rate(&self, claims: &[Active]) -> (Record, f64) {
        let trusted = claims.iter().any(|claim| claim.meaning.trusted);
        let usable = || claims.iter().filter(move |claim| self.accepted(claim, trusted));
        let service = usable()
            .filter(|claim| claim.meaning.service.is_some())
            .min_by_key(|claim| self.strength(claim));
        let provider = usable()
            .filter(|claim| claim.meaning.provider.is_some())
            .min_by_key(|claim| (self.strength(claim), claim.size));
        let user = claims
            .iter()
            .filter(|claim| !claim.baseline && claim.meaning.user.is_some())
            .min_by_key(|claim| {
                (claim.meaning.weak, claim.meaning.provider.is_none(), claim.size)
            });
        let mut record = Record {
            service: service.and_then(|claim| claim.meaning.service.clone()),
            evidence: service.and_then(|claim| claim.meaning.evidence.clone()),
            provider: provider.and_then(|claim| claim.meaning.provider.clone()),
            user_type: user.and_then(|claim| claim.meaning.user.clone()),
            ..Record::default()
        };
        let named = claims.iter().flat_map(|claim| &claim.meaning.flags);
        for flag in named {
            let bit = self.flags.iter().position(|known| known == flag);
            record.flags |= bit.map_or(0, |bit| 1 << bit);
        }
        let own: Vec<&Active> = claims.iter().filter(|claim| !claim.baseline).collect();
        let own_service = service.filter(|claim| !claim.baseline);
        let risk = self.risk(&own, trusted, own_service);
        if risk <= 0.0 {
            return (record, 0.0);
        }
        let risky = || own.iter().filter(|claim| claim.meaning.risk > 0);
        let groups: HashSet<&str> =
            risky().map(|claim| claim.meaning.group.as_str()).collect();
        let strongest = risky()
            .filter(|claim| claim.meaning.threat.is_some())
            .max_by_key(|claim| claim.meaning.risk);
        let windows = own
            .iter()
            .filter(|claim| claim.meaning.risk > 0 || claim.meaning.service.is_some());
        let percent = (risk.min(self.scoring.risk_cap) * 100.0).round() as u32;
        record.risk = (percent > 0).then_some(percent);
        record.threat = strongest.and_then(|claim| claim.meaning.threat.clone());
        record.reports = (!groups.is_empty()).then_some(groups.len() as u32);
        let window = windows.filter_map(|claim| claim.meaning.window).min();
        record.last_seen_days = window.map(|window| self.snap_days(window));
        (record, risk)
    }

    fn risk(&self, own: &[&Active], trusted: bool, service: Option<&Active>) -> f64 {
        let damping = if trusted { self.scoring.trusted.damping } else { 1.0 };
        let mut groups: BTreeMap<&str, f64> = BTreeMap::new();
        for claim in own {
            let risk = f64::from(claim.meaning.risk) / 1000.0 * damping;
            let entry = groups.entry(claim.meaning.group.as_str()).or_default();
            *entry = entry.max(risk);
        }
        let combined = 1.0 - groups.values().map(|risk| 1.0 - risk).product::<f64>();
        combined.max(service.map_or(0.0, |claim| self.service_floor(claim)))
    }

    fn blocklisted(&self, own: &[Active], risk: f64) -> bool {
        let trusted = own.iter().any(|claim| claim.meaning.trusted);
        !trusted && risk >= self.scoring.blocklist.minimum_risk
    }
}

fn inferred_meaning(scoring: &Scoring, feed: String, service: Option<&str>) -> Meaning {
    Meaning {
        feed,
        service: service.map(str::to_string),
        evidence: service.map(|_| scoring.inference.evidence.clone()),
        quality: per_mille(1.0),
        weak: true,
        ..Meaning::default()
    }
}

type Baselines = (Vec<Meaning>, HashMap<u32, Vec<u32>>);

fn baselines(
    claims: &Claims,
    networks: &Networks,
    text: &Text,
    scoring: &Scoring,
) -> Baselines {
    let inference = &scoring.inference;
    let mut meanings: Vec<Meaning> = claims.meanings.clone();
    let mut by_row: HashMap<u32, Vec<u32>> = HashMap::new();
    for &(asn, meaning) in &claims.asns {
        if let Some(&row) = networks.asn_rows.get(&asn) {
            by_row.entry(row).or_default().push(meaning);
        }
    }
    let fold_all =
        |names: &Vec<String>| names.iter().map(|name| text.fold(name)).collect();
    let services: Vec<(&String, Vec<String>)> =
        inference.services.iter().map(|(kind, names)| (kind, fold_all(names))).collect();
    let flags: Vec<(&String, Vec<String>)> =
        inference.flags.iter().map(|(flag, names)| (flag, fold_all(names))).collect();
    for (&asn, &row) in &networks.asn_rows {
        let network = &networks.rows[row as usize];
        let names = [network.handle.as_deref(), network.operator.company.as_deref()];
        let haystack =
            text.fold(&names.into_iter().flatten().collect::<Vec<_>>().join(" | "));
        let matches = |needles: &[String]| {
            needles.iter().any(|needle| text.contains_word(&haystack, needle))
        };
        let mut push = |meaning: Meaning| {
            meanings.push(meaning);
            by_row.entry(row).or_default().push(meanings.len() as u32 - 1);
        };
        for (service, needles) in &services {
            if matches(needles) {
                let mut meaning = inferred_meaning(
                    scoring,
                    format!("inferred:{service}"),
                    Some(service),
                );
                meaning.provider = network.operator.company.clone();
                push(meaning);
            }
        }
        for (flag, needles) in &flags {
            let listed =
                inference.flag_asns.get(*flag).is_some_and(|asns| asns.contains(&asn));
            if listed || matches(needles) {
                let mut meaning =
                    inferred_meaning(scoring, format!("inferred:{flag}"), None);
                meaning.flags = vec![flag.to_string()];
                push(meaning);
            }
        }
    }
    (meanings, by_row)
}

fn netname_claims(networks: &Networks, meanings: &mut Vec<Meaning>) -> Families<u32> {
    let mut ids: HashMap<&str, u32> = HashMap::new();
    networks.netname_users.each_ref().map(|spans| {
        spans
            .iter()
            .map(|span| {
                let id = *ids.entry(&span.value).or_insert_with(|| {
                    meanings.push(Meaning {
                        feed: format!("netname:{}", span.value),
                        user: Some(span.value.clone()),
                        quality: per_mille(1.0),
                        weak: true,
                        ..Meaning::default()
                    });
                    meanings.len() as u32 - 1
                });
                Span { first: span.first, last: span.last, value: id }
            })
            .collect()
    })
}

struct Collector {
    interner: Interner,
    spans: Families<u32>,
    hosts: [Vec<(Address, u32)>; 2],
    blocklist: Families<()>,
    reported: [HashMap<u32, f64>; 2],
}

pub fn build(
    claims: &Claims,
    networks: &Networks,
    text: &Text,
    flags: Vec<String>,
) -> Abuse {
    let scoring: Scoring = load_json("scoring.json");
    let rater = Rater { scoring: &scoring, flags };
    let (mut meanings, baseline) = baselines(claims, networks, text, &scoring);
    let netnamed = netname_claims(networks, &mut meanings);
    let mut collector = Collector {
        interner: Interner::default(),
        spans: [Vec::new(), Vec::new()],
        hosts: [Vec::new(), Vec::new()],
        blocklist: [Vec::new(), Vec::new()],
        reported: [HashMap::new(), HashMap::new()],
    };
    for (family_slot, named) in netnamed.into_iter().enumerate() {
        let claim_spans: Vec<Span<u32>> =
            claims.ranges[family_slot].iter().cloned().chain(named).collect();
        let network_spans = &networks.spans[family_slot];
        let mut ranges: Vec<(Address, Address)> =
            claim_spans.iter().map(|span| (span.first, span.last)).collect();
        ranges.extend(network_spans.iter().map(|span| (span.first, span.last)));
        let unit = if family_slot == 0 { 0 } else { scoring.network.v6_unit_bits };
        sweep(&ranges, |first, last, active| {
            let mut own: Vec<Active> = Vec::new();
            let mut network = None;
            for &index in active {
                let Some(span) = claim_spans.get(index) else {
                    network =
                        Some(network_spans[index - claim_spans.len()].value.network);
                    continue;
                };
                let meaning = &meanings[span.value as usize];
                own.push(Active {
                    meaning,
                    size: span.last - span.first,
                    baseline: false,
                });
            }
            let base = network.and_then(|row| baseline.get(&row)).into_iter().flatten();
            let base: Vec<Active> = base
                .map(|&id| Active {
                    meaning: &meanings[id as usize],
                    size: Address::MAX,
                    baseline: true,
                })
                .collect();
            let segment = Segment { family_slot, first, last, network, unit };
            collector.record(&rater, &segment, &own, &base);
        });
    }
    let network_risk =
        network_risks(claims, networks, &scoring, &collector.reported, &meanings);
    log(&format!(
        "abuse: {} records, spans v4 {} v6 {}, hosts v4 {} v6 {}",
        collector.interner.records.len(),
        collector.spans[0].len(),
        collector.spans[1].len(),
        collector.hosts[0].len(),
        collector.hosts[1].len()
    ));
    Abuse {
        records: collector.interner.records,
        spans: collector.spans,
        hosts: collector.hosts,
        network_risk,
        blocklist: collector.blocklist,
    }
}

struct Segment {
    family_slot: usize,
    first: Address,
    last: Address,
    network: Option<u32>,
    unit: u32,
}

impl Collector {
    fn record(
        &mut self,
        rater: &Rater,
        segment: &Segment,
        own: &[Active],
        base: &[Active],
    ) {
        let Segment { family_slot, first, last, network, unit } = *segment;
        let host = first == last && own.iter().any(|claim| claim.size == 0);
        let ranged = own.iter().filter(|claim| claim.size > 0 || !host);
        let range_claims: Vec<Active> = ranged.chain(base).copied().collect();
        let (range_record, mut risk) = rater.rate(&range_claims);
        if let Some(id) = self.interner.id(range_record.clone()) {
            push_merged(&mut self.spans[family_slot], first, last, id);
        }
        if host {
            let all: Vec<Active> = own.iter().chain(base).copied().collect();
            let (host_record, host_risk) = rater.rate(&all);
            risk = host_risk;
            if host_record != range_record
                && let Some(id) = self.interner.id(host_record)
            {
                self.hosts[family_slot].push((first, id));
            }
        }
        if rater.blocklisted(own, risk) {
            push_merged(&mut self.blocklist[family_slot], first, last, ());
        }
        if let Some(network) = network.filter(|_| risk > 0.0) {
            let size = ((last - first) as f64 + 1.0) / 2f64.powi(unit as i32);
            *self.reported[family_slot].entry(network).or_default() += risk * size;
        }
    }
}

fn network_risks(
    claims: &Claims,
    networks: &Networks,
    scoring: &Scoring,
    reported: &[HashMap<u32, f64>; 2],
    meanings: &[Meaning],
) -> HashMap<u32, u32> {
    let mut announced: [HashMap<u32, f64>; 2] = [HashMap::new(), HashMap::new()];
    for (family_slot, family) in networks.spans.iter().enumerate() {
        let unit = if family_slot == 0 { 0 } else { scoring.network.v6_unit_bits };
        for span in family.iter().filter(|span| span.value.rpki.is_some()) {
            let size = ((span.last - span.first) as f64 + 1.0) / 2f64.powi(unit as i32);
            *announced[family_slot].entry(span.value.network).or_default() += size;
        }
    }
    let mut own_feeds: HashMap<u32, Vec<f64>> = HashMap::new();
    for &(asn, meaning) in &claims.asns {
        let risk = meanings[meaning as usize].risk;
        if let (Some(&row), true) = (networks.asn_rows.get(&asn), risk > 0) {
            own_feeds.entry(row).or_default().push(f64::from(risk) / 1000.0);
        }
    }
    let mut rows: Vec<u32> = own_feeds.keys().copied().collect();
    rows.extend(reported.iter().flat_map(|family| family.keys().copied()));
    rows.sort_unstable();
    rows.dedup();
    let share = |row: u32, family_slot: usize| {
        let total = announced[family_slot].get(&row).copied().unwrap_or(0.0);
        let mass = reported[family_slot].get(&row).copied().unwrap_or(0.0);
        if total > 0.0 { (mass / total).min(1.0).sqrt() } else { 0.0 }
    };
    let mut risks = HashMap::new();
    for row in rows {
        let worst = share(row, 0).max(share(row, 1));
        let feeds = own_feeds.get(&row).into_iter().flatten();
        let risk =
            1.0 - feeds.chain([worst].iter()).map(|risk| 1.0 - risk).product::<f64>();
        if risk >= scoring.network.minimum {
            let percent = (risk.min(scoring.risk_cap) * 100.0).round().max(1.0) as u32;
            risks.insert(row, percent);
        }
    }
    risks
}

pub fn subtract(spans: &mut Vec<Span<()>>, reserved: &[Span<()>]) {
    let mut output = Vec::new();
    for span in spans.iter() {
        let mut start = Some(span.first);
        let holes = reserved
            .iter()
            .filter(|hole| hole.last >= span.first && hole.first <= span.last);
        for hole in holes {
            let Some(current) = start else {
                break;
            };
            if hole.first > current {
                output.push(Span { first: current, last: hole.first - 1, value: () });
            }
            start = hole
                .last
                .checked_add(1)
                .filter(|&next| next <= span.last)
                .map(|next| next.max(current));
        }
        if let Some(current) = start {
            output.push(Span { first: current, last: span.last, value: () });
        }
    }
    *spans = output;
}
