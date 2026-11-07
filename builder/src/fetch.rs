use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use chrono::{Datelike, Months, Utc};
use regex::Regex;
use serde::Deserialize;

use crate::text::Text;
use crate::{Environment, load_json};

#[derive(Deserialize, Clone, Default)]
#[serde(default)]
pub struct Source {
    pub name: String,
    pub url: Option<String>,
    pub urls: Vec<String>,
    pub listing: Option<String>,
    pub member: Option<String>,
    pub keep: Option<String>,
    pub pages: Option<[u64; 3]>,
    pub max_age_hours: Option<u64>,
    pub core: bool,
    pub lane: Option<String>,
    pub delay_seconds: u64,
    pub hosts: Option<String>,
    pub reject: Option<String>,
}

#[derive(Deserialize)]
struct GeofeedSettings {
    concurrency: usize,
    timeout_seconds: u64,
    max_bytes: u64,
    retries: u32,
    max_age_hours: u64,
    sources: Vec<String>,
}

#[derive(Deserialize)]
struct Settings {
    user_agent: String,
    concurrency: usize,
    retries: u32,
    timeout_seconds: u64,
    feed_max_age_hours: u64,
    max_bytes: Option<u64>,
    host_headers: HostHeaders,
    geofeeds: GeofeedSettings,
    sources: Vec<Source>,
}

#[derive(Deserialize)]
struct FeedSource {
    name: String,
    url: String,
    hosts: Option<String>,
}

const DEFAULT_MAX_BYTES: u64 = 2 << 30;
const UNPACK_FACTOR: u64 = 4;

type HostHeaders = HashMap<String, HashMap<String, String>>;

struct Client {
    agent: ureq::Agent,
    host_headers: HostHeaders,
    retries: u32,
    max_bytes: u64,
    environment: Environment,
}

pub fn run(environment: &Environment) -> io::Result<()> {
    let settings: Settings = load_json("sources.json");
    let feeds: Vec<FeedSource> = load_json("feeds.json");
    let mut sources = settings.sources.clone();
    sources.extend(feeds.into_iter().map(|feed| Source {
        name: format!("feeds/{}", feed.name),
        url: Some(feed.url),
        hosts: feed.hosts,
        max_age_hours: Some(settings.feed_max_age_hours),
        ..Source::default()
    }));
    fs::create_dir_all("inputs/feeds")?;
    let client = Client {
        agent: agent(&settings.user_agent, settings.timeout_seconds, true),
        host_headers: settings.host_headers.clone(),
        retries: settings.retries,
        max_bytes: settings.max_bytes.unwrap_or(DEFAULT_MAX_BYTES),
        environment: environment.clone(),
    };
    let lanes = group_lanes(sources);
    let failed_core = AtomicUsize::new(0);
    parallel(&lanes, settings.concurrency, |lane| {
        for (index, source) in lane.iter().enumerate() {
            if index > 0 && !fresh(&input_path(&source.name), source.max_age_hours) {
                std::thread::sleep(Duration::from_secs(source.delay_seconds));
            }
            if !fetch_source(&client, source) && source.core {
                failed_core.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    fetch_geofeeds(&settings, environment)?;
    if failed_core.load(Ordering::Relaxed) > 0 {
        return Err(io::Error::other("core source missing"));
    }
    Ok(())
}

pub fn input_path(name: &str) -> PathBuf {
    Path::new("inputs").join(name)
}

fn agent(user_agent: &str, timeout_seconds: u64, https_only: bool) -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(https_only)
        .user_agent(user_agent)
        .timeout_global(Some(Duration::from_secs(timeout_seconds)))
        .build()
        .into()
}

fn group_lanes(sources: Vec<Source>) -> Vec<Vec<Source>> {
    let mut lanes: Vec<Vec<Source>> = Vec::new();
    let mut named: HashMap<String, usize> = HashMap::new();
    for source in sources {
        let Some(lane) = source.lane.clone() else {
            lanes.push(vec![source]);
            continue;
        };
        let index = *named.entry(lane).or_insert_with(|| {
            lanes.push(Vec::new());
            lanes.len() - 1
        });
        lanes[index].push(source);
    }
    lanes
}

pub fn parallel<T: Sync>(items: &[T], threads: usize, work: impl Fn(&T) + Sync) {
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..threads.min(items.len()) {
            scope.spawn(|| {
                while let Some(item) = items.get(next.fetch_add(1, Ordering::Relaxed)) {
                    work(item);
                }
            });
        }
    });
}

fn fresh(path: &Path, max_age_hours: Option<u64>) -> bool {
    let Ok(modified) = fs::metadata(path).and_then(|metadata| metadata.modified()) else {
        return false;
    };
    let age = SystemTime::now().duration_since(modified).unwrap_or_default();
    age < Duration::from_secs(max_age_hours.unwrap_or(24) * 3600)
}

fn fetch_source(client: &Client, source: &Source) -> bool {
    let target = input_path(&source.name);
    if fresh(&target, source.max_age_hours) {
        log_size(&source.name, &target, "cached");
        return true;
    }
    let candidates: Vec<String> =
        source.url.iter().chain(&source.urls).cloned().collect();
    let mut last_error = String::from("no url");
    for template in candidates {
        let url = match expand(&template, &client.environment, 0) {
            Ok(url) => url,
            Err(missing) => {
                eprintln!("{:<40} skipped: {missing} not set", source.name);
                return false;
            }
        };
        match download_source(client, source, &url, &target) {
            Ok(()) => {
                log_size(&source.name, &target, "fetched");
                return true;
            }
            Err(error) => last_error = client.redact(&error.to_string()),
        }
    }
    eprintln!("{:<40} FAILED: {last_error}", source.name);
    false
}

fn log_size(name: &str, path: &Path, status: &str) {
    let bytes = fs::metadata(path).map(|metadata| metadata.len()).unwrap_or(0);
    eprintln!("{name:<40} {bytes:>13} bytes  {status}");
}

fn download_source(
    client: &Client,
    source: &Source,
    url: &str,
    target: &Path,
) -> io::Result<()> {
    let url = match &source.listing {
        Some(pattern) => resolve_listing(client, url, pattern)?,
        None => url.to_string(),
    };
    let download = target.with_extension("download");
    let mut file = BufWriter::new(File::create(&download)?);
    match source.pages {
        Some([start, stop, step]) => {
            for page in (start..=stop).step_by(step as usize) {
                let page_url = url.replace("{page}", &page.to_string());
                client.get(&page_url, &mut file)?;
                file.write_all(b"\n")?;
            }
        }
        None => client.get(&url, &mut file)?,
    }
    file.flush()?;
    drop(file);
    reject_body(&download, source.reject.as_deref())?;
    unpack(&download, target, source, client.max_bytes.saturating_mul(UNPACK_FACTOR))?;
    if let Some(pattern) = &source.hosts {
        resolve_hosts(target, pattern)?;
    }
    Ok(())
}

fn reject_body(path: &Path, pattern: Option<&str>) -> io::Result<()> {
    let Some(pattern) = pattern else {
        return Ok(());
    };
    let mut head = [0u8; 256];
    let length = File::open(path)?.read(&mut head)?;
    let pattern = regex::bytes::Regex::new(pattern).map_err(io::Error::other)?;
    if pattern.is_match(&head[..length]) {
        fs::remove_file(path)?;
        return Err(io::Error::other(
            String::from_utf8_lossy(&head[..length]).into_owned(),
        ));
    }
    Ok(())
}

fn resolve_listing(client: &Client, url: &str, pattern: &str) -> io::Result<String> {
    let mut page = Vec::new();
    client.get(url, &mut page)?;
    let pattern = Regex::new(pattern).map_err(io::Error::other)?;
    let page = String::from_utf8_lossy(&page);
    let newest = pattern.find_iter(&page).map(|found| found.as_str()).max();
    let newest = newest.ok_or_else(|| io::Error::other("listing has no match"))?;
    Ok(format!("{url}{newest}"))
}

pub fn expand(
    template: &str,
    environment: &Environment,
    months_back: u32,
) -> Result<String, String> {
    let now = Utc::now() - Months::new(months_back);
    let previous = now - Months::new(1);
    let dates = [
        ("month", now.format("%Y-%m").to_string()),
        ("previous_month", previous.format("%Y-%m").to_string()),
        ("year", now.year().to_string()),
        ("mm", format!("{:02}", now.month())),
        ("previous_year", previous.year().to_string()),
        ("previous_mm", format!("{:02}", previous.month())),
    ];
    let placeholder = Regex::new(r"\{([A-Za-z_]+)\}").expect("valid regex");
    let mut missing = None;
    let expanded = placeholder.replace_all(template, |captures: &regex::Captures| {
        let key = &captures[1];
        let date = dates.iter().find(|(name, _)| *name == key).map(|(_, value)| value);
        if let Some(value) = date.or_else(|| environment.get(key)) {
            return value.clone();
        }
        if key != "page" {
            missing = Some(key.to_string());
        }
        captures[0].to_string()
    });
    match missing {
        Some(key) => Err(key),
        None => Ok(expanded.into_owned()),
    }
}

impl Client {
    fn get(&self, url: &str, output: &mut impl Write) -> io::Result<()> {
        let mut attempt = 0;
        loop {
            let mut buffer = Vec::new();
            match self.try_get(url, &mut buffer) {
                Ok(()) => return output.write_all(&buffer),
                Err(error) if attempt + 1 >= self.retries => return Err(error),
                Err(_) => std::thread::sleep(Duration::from_secs(1 << attempt)),
            }
            attempt += 1;
        }
    }

    fn try_get(&self, url: &str, output: &mut Vec<u8>) -> io::Result<()> {
        let mut request = self.agent.get(url);
        let host = url.split("://").nth(1).and_then(|rest| rest.split('/').next());
        let headers =
            host.and_then(|host| self.host_headers.get(host)).into_iter().flatten();
        for (name, value) in headers {
            let value = expand(value, &self.environment, 0).map_err(io::Error::other)?;
            request = request.header(name, value);
        }
        let mut response = request.call().map_err(io::Error::other)?;
        copy_capped(response.body_mut().as_reader(), output, self.max_bytes)?;
        Ok(())
    }

    fn redact(&self, text: &str) -> String {
        let secrets = self.environment.values().filter(|value| value.len() >= 6);
        secrets.fold(text.to_string(), |text, secret| text.replace(secret, "***"))
    }
}

enum Packing {
    Gzip,
    Bzip2,
    Xz,
    Zip,
    Tar,
}

fn sniff(path: &Path) -> io::Result<Option<Packing>> {
    let mut head = [0u8; 512];
    let length = File::open(path)?.read(&mut head)?;
    let head = &head[..length];
    let packing = match head {
        [0x1f, 0x8b, ..] => Some(Packing::Gzip),
        [b'B', b'Z', b'h', ..] => Some(Packing::Bzip2),
        [0xfd, b'7', b'z', b'X', b'Z', 0, ..] => Some(Packing::Xz),
        [b'P', b'K', 3, 4, ..] => Some(Packing::Zip),
        _ if head.len() > 262 && &head[257..262] == b"ustar" => Some(Packing::Tar),
        _ => None,
    };
    Ok(packing)
}

fn copy_capped(
    reader: impl Read,
    output: &mut impl Write,
    limit: u64,
) -> io::Result<u64> {
    let copied = io::copy(&mut reader.take(limit.saturating_add(1)), output)?;
    if copied > limit {
        return Err(io::Error::other(format!("data exceeds {limit} bytes")));
    }
    Ok(copied)
}

fn unpack(download: &Path, target: &Path, source: &Source, limit: u64) -> io::Result<()> {
    let mut current = download.to_path_buf();
    let mut step = 0;
    while let Some(packing) = sniff(&current)? {
        step += 1;
        let next = target.with_extension(format!("unpack{step}"));
        let mut output = BufWriter::new(File::create(&next)?);
        let input = BufReader::new(File::open(&current)?);
        match packing {
            Packing::Gzip => copy_capped(
                flate2::bufread::MultiGzDecoder::new(input),
                &mut output,
                limit,
            ),
            Packing::Bzip2 => copy_capped(
                bzip2::bufread::MultiBzDecoder::new(input),
                &mut output,
                limit,
            ),
            Packing::Xz => copy_capped(
                liblzma::bufread::XzDecoder::new_multi_decoder(input),
                &mut output,
                limit,
            ),
            Packing::Zip => {
                extract_zip(&current, source.member.as_deref(), &mut output, limit)
            }
            Packing::Tar => {
                extract_tar(&current, source.member.as_deref(), &mut output, limit)
            }
        }?;
        output.flush()?;
        fs::remove_file(&current)?;
        current = next;
    }
    match &source.keep {
        Some(pattern) => {
            filter_lines(&current, target, pattern)?;
            fs::remove_file(&current)
        }
        None => fs::rename(&current, target),
    }
}

fn pick_member(entries: &[(String, u64)], member: Option<&str>) -> io::Result<usize> {
    let pattern = member.map(Regex::new).transpose().map_err(io::Error::other)?;
    let candidates = entries.iter().enumerate().filter(|(_, (name, _))| {
        pattern.as_ref().is_none_or(|pattern| pattern.is_match(name))
    });
    let largest = candidates.max_by_key(|(_, (_, size))| *size);
    largest.map(|(index, _)| index).ok_or_else(|| io::Error::other("no archive member"))
}

fn extract_zip(
    path: &Path,
    member: Option<&str>,
    output: &mut impl Write,
    limit: u64,
) -> io::Result<u64> {
    let mut archive =
        zip::ZipArchive::new(File::open(path)?).map_err(io::Error::other)?;
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(io::Error::other)?;
        entries.push((entry.name().map(String::from).unwrap_or_default(), entry.size()));
    }
    let index = pick_member(&entries, member)?;
    copy_capped(archive.by_index(index).map_err(io::Error::other)?, output, limit)
}

fn extract_tar(
    path: &Path,
    member: Option<&str>,
    output: &mut impl Write,
    limit: u64,
) -> io::Result<u64> {
    let mut archive = tar::Archive::new(File::open(path)?);
    let entries: Vec<(String, u64)> = archive
        .entries()?
        .filter_map(Result::ok)
        .map(|entry| {
            let name =
                entry.path().map(|path| path.display().to_string()).unwrap_or_default();
            (name, entry.size())
        })
        .collect();
    let index = pick_member(&entries, member)?;
    let mut archive = tar::Archive::new(File::open(path)?);
    let entry =
        archive.entries()?.nth(index).ok_or_else(|| io::Error::other("tar"))??;
    copy_capped(entry, output, limit)
}

fn filter_lines(input: &Path, output: &Path, pattern: &str) -> io::Result<()> {
    let pattern = regex::bytes::Regex::new(pattern).map_err(io::Error::other)?;
    let mut writer = BufWriter::new(File::create(output)?);
    for line in BufReader::new(File::open(input)?).split(b'\n') {
        let line = line?;
        let line = line.strip_suffix(b"\r").unwrap_or(&line);
        if pattern.is_match(line) {
            writer.write_all(line)?;
            writer.write_all(b"\n")?;
        }
    }
    writer.flush()
}

fn resolve_hosts(target: &Path, pattern: &str) -> io::Result<()> {
    let pattern = Regex::new(&format!("(?m){pattern}")).map_err(io::Error::other)?;
    let text = String::from_utf8_lossy(&fs::read(target)?).into_owned();
    let hosts: Vec<&str> = pattern.find_iter(&text).map(|found| found.as_str()).collect();
    let hosts: Vec<&str> =
        hosts.into_iter().collect::<BTreeSet<_>>().into_iter().collect();
    let addresses = std::sync::Mutex::new(BTreeSet::new());
    parallel(&hosts, 64, |host| {
        let Ok(resolved) = (*host, 0).to_socket_addrs() else {
            return;
        };
        let mut addresses = addresses.lock().expect("lock");
        addresses.extend(resolved.map(|address| address.ip().to_string()));
    });
    let lines: Vec<String> = addresses.into_inner().expect("lock").into_iter().collect();
    eprintln!("{:<40} resolved {} hosts", target.display(), hosts.len());
    fs::write(target.with_extension("resolved"), lines.join("\n"))
}

fn geofeed_urls(whois_text: &str, pattern: &Regex) -> Vec<String> {
    let urls = pattern.captures_iter(whois_text).map(|captures| captures[1].to_string());
    urls.collect::<BTreeSet<_>>().into_iter().collect()
}

pub fn geofeed_file(url: &str) -> PathBuf {
    let hash = url.bytes().fold(0xcbf29ce484222325u64, |hash, byte| {
        (hash ^ byte as u64).wrapping_mul(0x100000001b3)
    });
    input_path(&format!("geofeeds/{hash:016x}.csv"))
}

fn fetch_geofeeds(settings: &Settings, environment: &Environment) -> io::Result<()> {
    let geofeed = &settings.geofeeds;
    let text = Text::load();
    let reference = Regex::new(&text.patterns().geofeed_reference).expect("valid regex");
    let mut urls = BTreeSet::new();
    for name in &geofeed.sources {
        let bytes = fs::read(input_path(name)).unwrap_or_default();
        urls.extend(geofeed_urls(&String::from_utf8_lossy(&bytes), &reference));
    }
    fs::create_dir_all("inputs/geofeeds")?;
    let urls: Vec<String> = urls.into_iter().collect();
    let client = Client {
        agent: agent(&settings.user_agent, geofeed.timeout_seconds, false),
        host_headers: HostHeaders::new(),
        retries: geofeed.retries,
        max_bytes: geofeed.max_bytes,
        environment: environment.clone(),
    };
    let source =
        Source { keep: Some(text.patterns().geofeed_line.clone()), ..Source::default() };
    let fetched = AtomicUsize::new(0);
    parallel(&urls, geofeed.concurrency, |url| {
        let target = geofeed_file(url);
        if fresh(&target, Some(geofeed.max_age_hours)) {
            return;
        }
        if download_source(&client, &source, url, &target).is_err() {
            let _ = fs::write(&target, "");
            return;
        }
        fetched.fetch_add(1, Ordering::Relaxed);
    });
    let fetched = fetched.load(Ordering::Relaxed);
    eprintln!("{:<40} {fetched} of {} fetched", "geofeeds (whois)", urls.len());
    Ok(())
}
