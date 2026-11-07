use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::feeds::Claims;
use crate::fetch::{geofeed_file, input_path};
use crate::geo::walk_mmdb;
use crate::spans::{
    Address, Families, Span, bits, lookup, parse_range, pick, prefix_length, push_merged,
    slot, sweep,
};
use crate::text::{Text, decode_line};
use crate::whois::{organisations, range_objects};
use crate::{load_json, log};

#[derive(Deserialize)]
struct Limits {
    minimum_prefix: HashMap<String, u32>,
}

#[derive(Deserialize)]
pub struct Eyeball {
    users: u64,
    tier: u64,
    dominant_users: u64,
    category: String,
    mobile_category: String,
    mobile_names: Vec<String>,
}

#[derive(Deserialize)]
pub struct Categories {
    peeringdb: HashMap<String, String>,
    bgptools: HashMap<String, String>,
    asrank_ixp: String,
    strength: Vec<String>,
    covered_share: f64,
    domains: HashMap<String, String>,
    keywords: HashMap<String, Vec<String>>,
    eyeball: Eyeball,
}

#[derive(Deserialize)]
pub struct Reserved {
    pub registries: Vec<String>,
    pub reachable_column: usize,
    pub unreachable: Vec<String>,
    pub extra: Vec<String>,
}

#[derive(Deserialize)]
pub struct NetworkRules {
    routes: Limits,
    holders: Limits,
    whois: HashMap<String, String>,
    organisations: Vec<String>,
    lacnic: String,
    rir_names: HashMap<String, String>,
    pub reserved: Reserved,
    minimum_year: i64,
    pub categories: Categories,
    netnames: HashMap<String, Vec<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Registration {
    pub rir: u8,
    pub country: [u8; 2],
    pub year: Option<u16>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NetworkSpan {
    pub network: u32,
    pub prefix: Option<u8>,
    pub rpki: Option<u8>,
}

#[derive(Default, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Operator {
    pub company: Option<String>,
    pub category: Option<String>,
    pub website: Option<String>,
    pub address: Option<String>,
    pub country: Option<String>,
    pub abuse_email: Option<String>,
    pub since: Option<u64>,
    pub tier: Option<u64>,
    pub cone: Option<u64>,
}

#[derive(Default, Clone, Debug)]
pub struct NetworkRow {
    pub asn: Option<u32>,
    pub handle: Option<String>,
    pub operator: Operator,
    pub names: Vec<String>,
    pub users: Option<u64>,
    pub mobile_code: Option<String>,
}

pub struct Networks {
    pub rows: Vec<NetworkRow>,
    pub spans: Families<NetworkSpan>,
    pub registry: Families<Registration>,
    pub asn_rows: HashMap<u32, u32>,
    pub whois_geofeeds: Vec<WhoisGeofeed>,
    pub org_ranges: HashMap<String, Vec<(usize, Address, Address)>>,
    pub netname_users: Families<String>,
    pub list_categories: HashMap<u32, String>,
    pub rules: NetworkRules,
}

pub struct WhoisGeofeed {
    pub url: String,
    pub family: usize,
    pub first: Address,
    pub last: Address,
    pub org: Option<String>,
}

fn rir_list() -> Vec<String> {
    let schema: serde_json::Value = load_json("schema.json");
    serde_json::from_value(schema["vocabularies"]["rir"].clone()).expect("rir vocabulary")
}

fn lines(name: &str) -> Vec<String> {
    let bytes = fs::read(input_path(name)).unwrap_or_default();
    bytes.split(|&byte| byte == b'\n').map(decode_line).collect()
}

fn year_of(date: &str, minimum: i64) -> Option<u16> {
    let year: i64 = date.get(..4)?.parse().ok()?;
    (year >= minimum).then_some(year as u16)
}

fn registry(
    rirs: &[String],
    rules: &NetworkRules,
    minimum_year: i64,
) -> (Families<Registration>, HashMap<u32, Registration>) {
    let mut spans: Vec<(usize, Span<Registration>)> = Vec::new();
    let mut asns = HashMap::new();
    for line in lines("nro_delegated") {
        let columns: Vec<&str> = line.split('|').collect();
        if columns.len() < 7
            || columns[1] == "*"
            || !matches!(columns[6], "allocated" | "assigned")
        {
            continue;
        }
        let rir_name = rules
            .rir_names
            .get(&columns[0].to_lowercase())
            .map_or(columns[0], String::as_str);
        let Some(rir) = rirs.iter().position(|known| known == rir_name) else {
            continue;
        };
        let code = columns[1].as_bytes();
        let country = if code.len() == 2 { [code[0], code[1]] } else { [0, 0] };
        let registration = Registration {
            rir: rir as u8,
            country,
            year: year_of(columns[5], minimum_year),
        };
        let Ok(value) = columns[4].parse::<u128>() else {
            continue;
        };
        match columns[2] {
            "asn" => {
                let Ok(start) = columns[3].parse::<u32>() else {
                    continue;
                };
                for asn in start..start.saturating_add(value as u32) {
                    asns.insert(asn, registration);
                }
            }
            "ipv4" | "ipv6" => {
                let Some((family, first, _)) = parse_range(columns[3]) else {
                    continue;
                };
                let last = if family == 4 {
                    first + value - 1
                } else {
                    crate::spans::prefix_range(family, first, value as u32).1
                };
                spans.push((family, Span { first, last, value: registration }));
            }
            _ => {}
        }
    }
    let mut families = crate::spans::split_families(spans);
    for family in families.iter_mut() {
        family.sort_by_key(|span| span.first);
        let merged = std::mem::take(family);
        for span in merged {
            push_merged(family, span.first, span.last, span.value);
        }
    }
    (families, asns)
}

fn first_asn(text: &str) -> Option<u32> {
    text.split(['_', ',', '{', '}']).find_map(|part| part.trim().parse().ok())
}

type Vrps = HashMap<(usize, Address, u32), Vec<(u32, u32)>>;

fn load_vrps() -> Vrps {
    let mut vrps: Vrps = HashMap::new();
    for line in lines("vrps").iter().skip(1) {
        let columns: Vec<&str> = line.split(',').collect();
        if columns.len() < 3 {
            continue;
        }
        let asn = columns[0].trim_start_matches("AS").parse::<u32>();
        let Some((prefix, length)) = columns[1].split_once('/') else {
            continue;
        };
        let (Ok(asn), Ok(length), Ok(max_length)) =
            (asn, length.parse::<u32>(), columns[2].parse::<u32>())
        else {
            continue;
        };
        let Some((family, network, _)) = parse_range(&format!("{prefix}/{length}"))
        else {
            continue;
        };
        vrps.entry((family, network, length)).or_default().push((asn, max_length));
    }
    vrps
}

fn validate(vrps: &Vrps, family: usize, network: Address, length: u32, asn: u32) -> u8 {
    let mut covered = false;
    for covering_length in 0..=length {
        let (covering_network, _) =
            crate::spans::prefix_range(family, network, covering_length);
        for &(roa_asn, max_length) in
            vrps.get(&(family, covering_network, covering_length)).into_iter().flatten()
        {
            if roa_asn == asn && max_length >= length && asn != 0 {
                return 1;
            }
            covered = true;
        }
    }
    if covered { 2 } else { 0 }
}

struct Route {
    asn: u32,
    prefix: u8,
    rpki: u8,
}

fn routes(rules: &NetworkRules) -> Families<Route> {
    let vrps = load_vrps();
    let mut candidates: [Vec<Span<(u8, Route)>>; 2] = [Vec::new(), Vec::new()];
    for (name, family) in [("pfx2as_v4", 4), ("pfx2as_v6", 6)] {
        let minimum = rules.routes.minimum_prefix[&family.to_string()];
        for line in lines(name) {
            let columns: Vec<&str> = line.split('\t').collect();
            if columns.len() < 3 {
                continue;
            }
            let (Ok(length), Some(asn)) =
                (columns[1].parse::<u32>(), first_asn(columns[2]))
            else {
                continue;
            };
            let Some((parsed_family, first, last)) =
                parse_range(&format!("{}/{length}", columns[0]))
            else {
                continue;
            };
            if parsed_family != family || length < minimum {
                continue;
            }
            let rpki = validate(&vrps, family, first, length, asn);
            let route = Route { asn, prefix: length as u8, rpki };
            candidates[slot(family)].push(Span { first, last, value: (0, route) });
        }
    }
    for line in lines("iptoasn") {
        let columns: Vec<&str> = line.split('\t').collect();
        if columns.len() < 3 {
            continue;
        }
        let Ok(asn) = columns[2].parse::<u32>() else {
            continue;
        };
        let (Some((family, first, _)), Some((_, last, _))) =
            (parse_range(columns[0]), parse_range(columns[1]))
        else {
            continue;
        };
        if asn == 0 {
            continue;
        }
        for (start, length) in crate::spans::aligned_blocks(family, first, last) {
            let (_, end) = crate::spans::prefix_range(family, start, length);
            let rpki = validate(&vrps, family, start, length, asn);
            let route = Route { asn, prefix: length as u8, rpki };
            candidates[slot(family)].push(Span {
                first: start,
                last: end,
                value: (1, route),
            });
        }
    }
    candidates.map(|family| {
        let picked = pick(&family, |span| (span.value.0, span.last - span.first));
        picked
            .into_iter()
            .map(|span| {
                let route = &family[span.value].value.1;
                let copy =
                    Route { asn: route.asn, prefix: route.prefix, rpki: route.rpki };
                Span { first: span.first, last: span.last, value: copy }
            })
            .collect()
    })
}

type As2Org = (String, Option<String>, Option<String>, Option<String>);

struct Sources {
    asn_names: HashMap<u32, (String, String, Option<String>)>,
    as2org: HashMap<u32, As2Org>,
    tiers: HashMap<u32, u64>,
    asrank: HashMap<u32, (Option<u64>, bool)>,
    peeringdb: HashMap<u32, Value>,
    peeringdb_orgs: HashMap<u64, Value>,
    lacnic_cities: HashMap<u32, String>,
    abuse: HashMap<u32, String>,
    bgptools: HashMap<u32, String>,
    users: HashMap<u32, u64>,
    ipinfo: HashMap<u32, (Option<String>, Option<String>)>,
}

fn load_sources(rules: &NetworkRules) -> Sources {
    let mut sources = Sources {
        asn_names: HashMap::new(),
        as2org: HashMap::new(),
        tiers: load_tiers(),
        asrank: HashMap::new(),
        peeringdb: HashMap::new(),
        peeringdb_orgs: HashMap::new(),
        lacnic_cities: HashMap::new(),
        abuse: HashMap::new(),
        bgptools: HashMap::new(),
        users: HashMap::new(),
        ipinfo: HashMap::new(),
    };
    for line in lines("ripe_asnames") {
        let Some((asn, rest)) = line.split_once(' ') else {
            continue;
        };
        let Ok(asn) = asn.parse::<u32>() else {
            continue;
        };
        let (handle, company) =
            rest.split_once(" - ").or_else(|| rest.split_once(' ')).unwrap_or((rest, ""));
        let (company, country) = match company.rsplit_once(", ") {
            Some((company, country)) if country.len() == 2 => {
                (company, Some(country.to_string()))
            }
            _ => (company, None),
        };
        sources.asn_names.insert(asn, (handle.to_string(), company.to_string(), country));
    }
    load_as2org(&mut sources, rules);
    load_asrank(&mut sources);
    load_peeringdb(&mut sources);
    load_lacnic(&mut sources, rules);
    for line in lines("abuse_contacts").iter().skip(1) {
        if let Some((asn, mail)) = line.split_once('\t')
            && let Ok(asn) = asn.parse()
        {
            sources.abuse.insert(asn, mail.trim().to_string());
        }
    }
    for line in lines("bgptools_asns").iter().skip(1) {
        let columns: Vec<&str> = line.split(',').collect();
        let asn =
            columns.first().and_then(|asn| asn.trim_start_matches("AS").parse().ok());
        if let (Some(asn), Some(class)) =
            (asn, columns.len().checked_sub(2).map(|index| columns[index]))
        {
            sources.bgptools.insert(asn, class.to_string());
        }
    }
    load_aspop(&mut sources);
    load_mmdb_asns(&mut sources);
    sources
}

fn load_tiers() -> HashMap<u32, u64> {
    let mut sells: HashSet<u32> = HashSet::new();
    let mut buys: HashSet<u32> = HashSet::new();
    let mut peers: HashSet<u32> = HashSet::new();
    for line in lines("caida_asrel") {
        if line.starts_with('#') {
            continue;
        }
        let columns: Vec<&str> = line.split('|').collect();
        if columns.len() < 3 {
            continue;
        }
        let (Ok(left), Ok(right)) =
            (columns[0].parse::<u32>(), columns[1].parse::<u32>())
        else {
            continue;
        };
        if columns[2] == "-1" {
            sells.insert(left);
            buys.insert(right);
        } else {
            peers.extend([left, right]);
        }
    }
    let all: BTreeSet<u32> = sells.iter().chain(&buys).copied().collect();
    let tier = |asn: &u32| match (sells.contains(asn), buys.contains(asn)) {
        (true, false) => 1,
        (true, true) => 2,
        _ => 3,
    };
    all.iter().map(|asn| (*asn, tier(asn))).collect()
}

fn load_as2org(sources: &mut Sources, rules: &NetworkRules) {
    let mut organisations: HashMap<String, (String, String, String)> = HashMap::new();
    let mut autonomous: Vec<(u32, String, String, String)> = Vec::new();
    let mut section = "";
    for line in lines("caida_as2org") {
        if line.starts_with("# format:org_id") {
            section = "org";
        } else if line.starts_with("# format:aut") {
            section = "aut";
        }
        if line.starts_with('#') {
            continue;
        }
        let columns: Vec<&str> = line.split('|').collect();
        match (section, columns.len()) {
            ("org", 5) => {
                let value = (
                    columns[2].to_string(),
                    columns[3].to_string(),
                    columns[4].to_string(),
                );
                organisations.insert(columns[0].to_string(), value);
            }
            ("aut", 6) => {
                let Ok(asn) = columns[0].parse() else {
                    continue;
                };
                autonomous.push((
                    asn,
                    columns[2].to_string(),
                    columns[3].to_string(),
                    columns[5].to_string(),
                ));
            }
            _ => {}
        }
    }
    for (asn, handle, org, source) in autonomous {
        let (company, country, _) = organisations.get(&org).cloned().unwrap_or_default();
        let rir = rules.rir_names.get(&source.to_lowercase()).cloned();
        let present = |text: String| (!text.is_empty()).then_some(text);
        sources.as2org.insert(asn, (handle, present(company), present(country), rir));
    }
}

fn load_asrank(sources: &mut Sources) {
    for line in lines("caida_asrank") {
        let Ok(page) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let edges = page["data"]["asns"]["edges"].as_array().cloned().unwrap_or_default();
        for edge in edges {
            let node = &edge["node"];
            let Some(asn) = node["asn"].as_str().and_then(|asn| asn.parse().ok()) else {
                continue;
            };
            let cone = node["cone"]["numberAsns"].as_u64();
            let exchange = !node["ixp"].is_null() && node["ixp"] != Value::Bool(false);
            sources.asrank.insert(asn, (cone, exchange));
        }
    }
}

fn load_peeringdb(sources: &mut Sources) {
    let read = |name: &str| -> Vec<Value> {
        let text = fs::read_to_string(input_path(name)).unwrap_or_default();
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        value["data"].as_array().cloned().unwrap_or_default()
    };
    for net in read("peeringdb_net") {
        if let Some(asn) = net["asn"].as_u64() {
            sources.peeringdb.insert(asn as u32, net);
        }
    }
    for org in read("peeringdb_org") {
        if let Some(id) = org["id"].as_u64() {
            sources.peeringdb_orgs.insert(id, org);
        }
    }
}

fn load_lacnic(sources: &mut Sources, rules: &NetworkRules) {
    crate::whois::blocks(&input_path(&rules.lacnic), |attributes| {
        let get = |key: &str| {
            attributes.iter().find(|(name, _)| name == key).map(|(_, value)| value)
        };
        let asn = get("aut-num")
            .and_then(|asn| asn.trim_start_matches("AS").parse::<u32>().ok());
        if let (Some(asn), Some(city)) =
            (asn, get("city").filter(|city| !city.is_empty()))
        {
            sources.lacnic_cities.insert(asn, city.clone());
        }
    });
}

fn load_aspop(sources: &mut Sources) {
    let text = fs::read_to_string(input_path("apnic_aspop")).unwrap_or_default();
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    for entry in value["Data"].as_array().into_iter().flatten() {
        if let (Some(asn), Some(users)) = (entry["AS"].as_u64(), entry["Users"].as_u64())
        {
            *sources.users.entry(asn as u32).or_default() += users;
        }
    }
}

fn load_mmdb_asns(sources: &mut Sources) {
    #[derive(Deserialize)]
    struct Ipinfo<'a> {
        #[serde(borrow, default)]
        asn: Option<&'a str>,
        #[serde(borrow, default)]
        as_name: Option<&'a str>,
        #[serde(borrow, default)]
        as_domain: Option<&'a str>,
    }
    walk_mmdb(&input_path("ipinfo_lite"), |_, _, _, result| {
        let Ok(Some(record)) = result.decode::<Ipinfo>() else {
            return;
        };
        let Some(asn) =
            record.asn.and_then(|asn| asn.trim_start_matches("AS").parse::<u32>().ok())
        else {
            return;
        };
        sources.ipinfo.entry(asn).or_insert_with(|| {
            (record.as_name.map(str::to_string), record.as_domain.map(str::to_string))
        });
    });
}

fn text_of(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| !text.is_empty())
}

fn operator_row(
    asn: u32,
    sources: &Sources,
    registration: Option<&Registration>,
    text: &Text,
) -> NetworkRow {
    let net = sources.peeringdb.get(&asn);
    let org = net
        .and_then(|net| net["org_id"].as_u64())
        .and_then(|id| sources.peeringdb_orgs.get(&id));
    let field = |value: Option<&Value>, key: &str| {
        value.and_then(|value| text_of(&value[key])).map(str::to_string)
    };
    let names = sources.asn_names.get(&asn);
    let as2org = sources.as2org.get(&asn);
    let ipinfo = sources.ipinfo.get(&asn);
    let handle =
        names.map(|names| names.0.clone()).or_else(|| as2org.map(|org| org.0.clone()));
    let handle = handle.and_then(|handle| text.clean(&handle));
    let company_candidates = [
        names.map(|names| names.1.clone()),
        as2org.and_then(|org| org.1.clone()),
        field(org, "name"),
        ipinfo.and_then(|info| info.0.clone()),
    ];
    let company = company_candidates
        .into_iter()
        .flatten()
        .find_map(|company| text.company(&company));
    let website = [
        field(net, "website"),
        field(org, "website"),
        ipinfo.and_then(|info| info.1.clone()),
    ]
    .into_iter()
    .flatten()
    .find_map(|website| text.website(&website));
    let country = [
        field(org, "country"),
        as2org.and_then(|org| org.2.clone()),
        names.and_then(|names| names.2.clone()),
        registration.map(|registration| {
            String::from_utf8_lossy(&registration.country).to_string()
        }),
    ];
    let country =
        country.into_iter().flatten().find(|code| code.len() == 2 && code != "ZZ");
    let city = field(org, "city").or_else(|| sources.lacnic_cities.get(&asn).cloned());
    let state_postal = [field(org, "state"), field(org, "zipcode")];
    let state_postal = state_postal.into_iter().flatten().collect::<Vec<_>>().join(" ");
    let parts = [field(org, "address1"), city, Some(state_postal)];
    let address = parts.into_iter().flatten().filter_map(|part| text.clean(&part));
    let address = address.collect::<Vec<_>>().join(", ");
    let operator = Operator {
        company,
        category: None,
        website,
        address: (!address.is_empty()).then_some(address),
        country,
        abuse_email: sources.abuse.get(&asn).and_then(|mail| text.mailbox(mail)),
        since: registration.and_then(|registration| registration.year).map(u64::from),
        tier: sources.tiers.get(&asn).copied(),
        cone: sources.asrank.get(&asn).and_then(|rank| rank.0),
    };
    let mut names_list: Vec<String> =
        [field(net, "name"), field(net, "aka"), field(net, "name_long")]
            .into_iter()
            .flatten()
            .collect();
    names_list.extend(operator.company.clone());
    names_list.extend(handle.clone());
    NetworkRow {
        asn: Some(asn),
        handle,
        operator,
        names: names_list,
        users: sources.users.get(&asn).copied(),
        mobile_code: None,
    }
}

fn strongest_category(
    candidates: &[Option<String>],
    categories: &Categories,
) -> Option<String> {
    let rank = |category: &String| {
        categories.strength.iter().position(|known| known == category)
    };
    candidates
        .iter()
        .flatten()
        .filter_map(|category| Some((rank(category)?, category)))
        .min()
        .map(|(_, category)| category.clone())
}

fn covered_categories(
    claims: &Claims,
    routes: &Families<Route>,
    categories: &Categories,
) -> HashMap<u32, String> {
    let mut covered: HashMap<(usize, u32, &str), f64> = HashMap::new();
    let mut totals: HashMap<(usize, u32), f64> = HashMap::new();
    for (family_slot, family_routes) in routes.iter().enumerate() {
        let users: Vec<(&Span<u32>, &str)> = claims.ranges[family_slot]
            .iter()
            .filter_map(|span| {
                let meaning = &claims.meanings[span.value as usize];
                meaning.provider.as_ref()?;
                Some((span, meaning.user.as_deref()?))
            })
            .collect();
        let mut ranges: Vec<(Address, Address)> =
            family_routes.iter().map(|span| (span.first, span.last)).collect();
        ranges.extend(users.iter().map(|(span, _)| (span.first, span.last)));
        sweep(&ranges, |first, last, active| {
            let Some(&route) = active.iter().find(|&&index| index < family_routes.len())
            else {
                return;
            };
            let asn = family_routes[route].value.asn;
            let size = (last - first) as f64 + 1.0;
            *totals.entry((family_slot, asn)).or_default() += size;
            let found: HashSet<&str> = active
                .iter()
                .filter_map(|index| index.checked_sub(family_routes.len()))
                .map(|index| users[index].1)
                .collect();
            for user in found {
                *covered.entry((family_slot, asn, user)).or_default() += size;
            }
        });
    }
    let mut qualified: HashMap<u32, Vec<Option<String>>> = HashMap::new();
    for ((family_slot, asn, user), size) in covered {
        if size / totals[&(family_slot, asn)] >= categories.covered_share {
            qualified.entry(asn).or_default().push(Some(user.to_string()));
        }
    }
    qualified
        .into_iter()
        .filter_map(|(asn, users)| Some((asn, strongest_category(&users, categories)?)))
        .collect()
}

pub fn domain_category(
    website: Option<&str>,
    mailbox: Option<&str>,
    categories: &Categories,
) -> Option<String> {
    let rules = &categories.domains;
    let hosts = [
        website.map(|site| site.split('/').next().unwrap_or(site)),
        mailbox.and_then(|mail| mail.split_once('@').map(|(_, domain)| domain)),
    ];
    for host in hosts.into_iter().flatten() {
        let mut matches: Vec<&String> = rules
            .iter()
            .filter(|(_, pattern)| {
                Regex::new(pattern).is_ok_and(|pattern| pattern.is_match(host))
            })
            .map(|(category, _)| category)
            .collect();
        matches.sort();
        if let Some(category) = matches.first() {
            return Some((*category).clone());
        }
    }
    None
}

pub fn keyword_category(
    names: &[String],
    categories: &Categories,
    text: &Text,
) -> Option<String> {
    let haystack = text.fold(&names.join(" | "));
    let mut keywords: Vec<(&String, &Vec<String>)> = categories.keywords.iter().collect();
    keywords.sort();
    for (category, words) in keywords {
        if words.iter().any(|word| text.contains_word(&haystack, &text.fold(word))) {
            return Some(category.clone());
        }
    }
    None
}

pub fn users_category(
    row: &NetworkRow,
    categories: &Categories,
    text: &Text,
) -> Option<String> {
    let eyeball = &categories.eyeball;
    let users = row.users.unwrap_or_default();
    let stub = row.operator.tier.is_none_or(|tier| tier == eyeball.tier);
    if users <= eyeball.users || !(stub || users >= eyeball.dominant_users) {
        return None;
    }
    let haystack = text.fold(&row.names.join(" | "));
    let mobile = eyeball
        .mobile_names
        .iter()
        .any(|name| text.contains_word(&haystack, &text.fold(name)));
    Some(if mobile { &eyeball.mobile_category } else { &eyeball.category }.clone())
}

fn list_sources(
    asn: u32,
    sources: &Sources,
    asn_users: &HashMap<u32, Vec<String>>,
    covered: &HashMap<u32, String>,
    categories: &Categories,
) -> (Vec<Option<String>>, Vec<Option<String>>) {
    let peeringdb = sources
        .peeringdb
        .get(&asn)
        .and_then(|net| text_of(&net["info_type"]))
        .and_then(|kind| categories.peeringdb.get(kind).cloned());
    let bgptools = sources
        .bgptools
        .get(&asn)
        .and_then(|class| categories.bgptools.get(class).cloned());
    let exchange = sources
        .asrank
        .get(&asn)
        .is_some_and(|rank| rank.1)
        .then(|| categories.asrank_ixp.clone());
    let primary = vec![peeringdb, bgptools, exchange, covered.get(&asn).cloned()];
    let tags = asn_users.get(&asn).into_iter().flatten().cloned().map(Some).collect();
    (primary, tags)
}

fn categorize(
    row: &mut NetworkRow,
    (primary, tags): (Vec<Option<String>>, Vec<Option<String>>),
    categories: &Categories,
    text: &Text,
) -> Option<String> {
    let operator = &row.operator;
    let eyeball = users_category(row, categories, text);
    let household = |category: &String| {
        [&categories.eyeball.category, &categories.eyeball.mobile_category]
            .contains(&category)
    };
    let declared = tags.iter().flatten().any(household);
    let tags =
        tags.into_iter().filter(|tag| !declared || tag.as_ref().is_some_and(household));
    let lists: Vec<Option<String>> = primary.into_iter().chain(tags).collect();
    let lists = lists.as_slice();
    let listed = strongest_category(lists, categories);
    let named = domain_category(
        operator.website.as_deref(),
        operator.abuse_email.as_deref(),
        categories,
    )
    .or_else(|| keyword_category(&row.names, categories, text));
    row.operator.category = match listed {
        Some(_) => strongest_category(&[lists, &[eyeball]].concat(), categories),
        None => named.or(eyeball),
    };
    listed
}

struct MobileCode {
    needle: String,
    code: String,
}

fn mobile_codes(text: &Text) -> HashMap<String, Vec<MobileCode>> {
    let mut codes: HashMap<String, Vec<MobileCode>> = HashMap::new();
    let mut add = |country: &str, name: &str, mcc: &str, mnc: &str| {
        let code = MobileCode { needle: text.fold(name), code: format!("{mcc}-{mnc}") };
        codes.entry(country.to_uppercase()).or_default().push(code);
    };
    let json = fs::read_to_string(input_path("mcc_mnc")).unwrap_or_default();
    let entries: Vec<Value> = serde_json::from_str(&json).unwrap_or_default();
    for entry in entries {
        let country = text_of(&entry["countryCode"]).unwrap_or_default();
        let country: String = country.chars().take(2).collect();
        let (Some(mcc), Some(mnc)) = (text_of(&entry["mcc"]), text_of(&entry["mnc"]))
        else {
            continue;
        };
        for name in [&entry["brand"], &entry["operator"]].into_iter().filter_map(text_of)
        {
            add(&country, name, mcc, mnc);
        }
    }
    for line in lines("mcc_mnc_table").iter().skip(1) {
        let columns: Vec<&str> = line.split(',').collect();
        if columns.len() >= 8 {
            add(columns[4], columns[7].trim_matches('"'), columns[0], columns[2]);
        }
    }
    codes
}

fn assign_carrier(
    row: &mut NetworkRow,
    codes: &HashMap<String, Vec<MobileCode>>,
    eyeball: &Eyeball,
    text: &Text,
) {
    let category = row.operator.category.as_ref();
    let cellular = category == Some(&eyeball.mobile_category);
    let subscribers = category == Some(&eyeball.category) && row.users.is_some();
    if !cellular && !subscribers {
        return;
    }
    let country = row.operator.country.clone().unwrap_or_default();
    let haystack = text.fold(&row.names.join(" | "));
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for code in codes.get(&country).into_iter().flatten() {
        if text.contains_word(&haystack, &code.needle) {
            *counts.entry(&code.code).or_default() += 1;
        }
    }
    let best =
        counts.into_iter().max_by_key(|(code, count)| (*count, std::cmp::Reverse(*code)));
    row.mobile_code = best.map(|(code, _)| code.to_string());
}

pub fn build(text: &Text, claims: &Claims) -> Networks {
    let rules: NetworkRules = load_json("network.json");
    let rirs = rir_list();
    let (registry, registered_asns) = registry(&rirs, &rules, rules.minimum_year);
    let routes = routes(&rules);
    log(&format!("routes: v4 {} v6 {}", routes[0].len(), routes[1].len()));
    let sources = load_sources(&rules);
    let mut asn_users: HashMap<u32, Vec<String>> = HashMap::new();
    for &(asn, meaning) in &claims.asns {
        if let Some(user) = &claims.meanings[meaning as usize].user {
            asn_users.entry(asn).or_default().push(user.clone());
        }
    }
    let covered = covered_categories(claims, &routes, &rules.categories);
    let mut asns: BTreeSet<u32> =
        routes.iter().flatten().map(|span| span.value.asn).collect();
    asns.extend(sources.asn_names.keys());
    let codes = mobile_codes(text);
    let mut rows = Vec::new();
    let mut asn_rows = HashMap::new();
    let mut list_categories = HashMap::new();
    for asn in asns {
        let registration = registered_asns.get(&asn);
        let mut row = operator_row(asn, &sources, registration, text);
        let lists = list_sources(asn, &sources, &asn_users, &covered, &rules.categories);
        if let Some(listed) = categorize(&mut row, lists, &rules.categories, text) {
            list_categories.insert(asn, listed);
        }
        assign_carrier(&mut row, &codes, &rules.categories.eyeball, text);
        asn_rows.insert(asn, rows.len() as u32);
        rows.push(row);
    }
    let whois = load_whois(&rules, &routes, &registry, &rirs, text);
    let holders = whois.holders;
    let mut spans: Families<NetworkSpan> = [Vec::new(), Vec::new()];
    for family_slot in 0..2 {
        let mut candidates: Vec<Span<(u8, NetworkSpan)>> = Vec::new();
        for span in &routes[family_slot] {
            let route = &span.value;
            let value = NetworkSpan {
                network: asn_rows[&route.asn],
                prefix: Some(route.prefix),
                rpki: Some(route.rpki),
            };
            candidates.push(Span {
                first: span.first,
                last: span.last,
                value: (0, value),
            });
        }
        for (holder, family, first, last) in &holders {
            if slot(*family) != family_slot {
                continue;
            }
            let row_index = rows.len() as u32;
            rows.push(holder.clone());
            let prefix = prefix_length(*family, *first, *last).map(|length| length as u8);
            let value = NetworkSpan { network: row_index, prefix, rpki: None };
            candidates.push(Span { first: *first, last: *last, value: (1, value) });
        }
        candidates.sort_by_key(|span| span.first);
        let picked = pick(&candidates, |span| {
            let size = span.last - span.first;
            (span.value.0, if span.value.0 == 0 { size } else { Address::MAX - size })
        });
        let mut output = Vec::new();
        for span in picked {
            push_merged(
                &mut output,
                span.first,
                span.last,
                candidates[span.value].value.1,
            );
        }
        spans[family_slot] = output;
    }
    log(&format!("networks: {} rows, {} holders", rows.len(), holders.len()));
    Networks {
        rows,
        spans,
        registry,
        asn_rows,
        whois_geofeeds: whois.geofeeds,
        org_ranges: whois.org_ranges,
        netname_users: whois.users,
        list_categories,
        rules,
    }
}

#[derive(Default)]
struct Whois {
    holders: Vec<(NetworkRow, usize, Address, Address)>,
    geofeeds: Vec<WhoisGeofeed>,
    org_ranges: HashMap<String, Vec<(usize, Address, Address)>>,
    users: Families<String>,
}

fn netname_user(netname: &str, words: &HashMap<String, Vec<String>>) -> Option<String> {
    let tokens: HashSet<String> = netname
        .split(|character: char| !character.is_alphanumeric())
        .map(str::to_lowercase)
        .collect();
    let mut found =
        words.iter().filter(|(_, list)| list.iter().any(|word| tokens.contains(word)));
    let (user, _) = found.next()?;
    found.next().is_none().then(|| user.clone())
}

fn load_whois(
    rules: &NetworkRules,
    routes: &Families<Route>,
    registry: &Families<Registration>,
    rirs: &[String],
    text: &Text,
) -> Whois {
    let organisation_paths: Vec<_> =
        rules.organisations.iter().map(|name| input_path(name)).collect();
    let organisation_refs: Vec<&std::path::Path> =
        organisation_paths.iter().map(|path| path.as_path()).collect();
    let org_names = organisations(&organisation_refs);
    let url_pattern = Regex::new(&text.patterns().whois_geofeed_url).expect("regex");
    let mut whois = Whois::default();
    let mut whois_names: Vec<(&String, &String)> = rules.whois.iter().collect();
    whois_names.sort();
    for (name, rir_name) in whois_names {
        let rir = rirs.iter().position(|known| known == rir_name).map(|rir| rir as u8);
        range_objects(&input_path(name), |object| {
            let org = object.get("org").map(str::to_string);
            if let Some(org) = &org {
                let range = (object.family, object.first, object.last);
                whois.org_ranges.entry(org.clone()).or_default().push(range);
            }
            if let Some(url) = geofeed_url(&object, &url_pattern)
                && geofeed_file(&url).exists()
            {
                let (family, first, last) = (object.family, object.first, object.last);
                whois.geofeeds.push(WhoisGeofeed {
                    url,
                    family,
                    first,
                    last,
                    org: org.clone(),
                });
            }
            let family_slot = slot(object.family);
            let user = object
                .get("netname")
                .and_then(|name| netname_user(name, &rules.netnames));
            if let Some(user) = user {
                let span = Span { first: object.first, last: object.last, value: user };
                whois.users[family_slot].push(span);
            }
            let minimum = rules.holders.minimum_prefix[&object.family.to_string()];
            let wide = prefix_width(object.family, object.first, object.last) < minimum;
            let routed = lookup(&routes[family_slot], object.first).is_some();
            let delegated =
                lookup(&registry[family_slot], object.first).map(|entry| entry.rir);
            if wide || routed || delegated != rir || rir.is_none() {
                return None::<()>;
            }
            let row = holder_row(&object, org.as_deref(), &org_names, text);
            whois.holders.push((row, object.family, object.first, object.last));
            None
        });
    }
    log(&format!(
        "whois: {} holders, {} geofeed references, {} typed netnames",
        whois.holders.len(),
        whois.geofeeds.len(),
        whois.users[0].len() + whois.users[1].len()
    ));
    whois
}

fn geofeed_url(object: &crate::whois::WhoisObject, pattern: &Regex) -> Option<String> {
    object.attributes.iter().find_map(|(key, value)| {
        let value = match key.as_str() {
            "geofeed" => value.as_str(),
            "remarks" => value.strip_prefix_ci("geofeed")?,
            _ => return None,
        };
        pattern.captures(value.trim()).map(|captures| captures[1].to_string())
    })
}

fn holder_row(
    object: &crate::whois::WhoisObject,
    org: Option<&str>,
    org_names: &HashMap<String, String>,
    text: &Text,
) -> NetworkRow {
    let description = object.attributes.iter().find(|(key, _)| key == "descr");
    let company = org
        .and_then(|org| org_names.get(org))
        .or(description.map(|(_, value)| value))
        .and_then(|company| text.company(company));
    let handle = object.get("netname").and_then(|name| text.clean(name));
    let country = object.get("country").map(str::to_uppercase);
    let country = country.filter(|code| code.len() == 2 && code != "EU" && code != "ZZ");
    let operator = Operator { company, country, ..Operator::default() };
    NetworkRow { handle, operator, ..NetworkRow::default() }
}

fn prefix_width(family: usize, first: Address, last: Address) -> u32 {
    let size = last - first;
    bits(family) - (128 - size.leading_zeros())
}

trait StripPrefixIgnoringCase {
    fn strip_prefix_ci(&self, prefix: &str) -> Option<&str>;
}

impl StripPrefixIgnoringCase for String {
    fn strip_prefix_ci(&self, prefix: &str) -> Option<&str> {
        let head = self.get(..prefix.len())?;
        head.eq_ignore_ascii_case(prefix).then(|| &self[prefix.len()..])
    }
}
