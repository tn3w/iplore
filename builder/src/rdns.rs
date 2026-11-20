use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::iter::Peekable;
use std::net::Ipv4Addr;
use std::time::Instant;

use liblzma::read::XzDecoder;
use liblzma::stream::PRESET_EXTREME;
use rayon::prelude::*;
use reader::rdns::{LZMA_SETTINGS, MAGIC, Run, SEPARATOR, WINDOW, push_varint};

use crate::log;
use crate::template::{renders, template};
use crate::write::lzma;

const DUMP: &str = "inputs/rdns-v4.tsv.xz";
const OUTPUT: &str = "dist/rdns-v4.rdns";
const BLOCK_BYTES: usize = 1 << 20;
const BATCH_BLOCKS: usize = 64;

struct Record {
    ip: u32,
    hosts: Vec<Vec<u8>>,
}

#[derive(Default)]
struct Packed {
    index: Vec<u8>,
    data: Vec<u8>,
    blocks: u32,
    runs: usize,
}

pub fn run() -> io::Result<()> {
    let started = Instant::now();
    pack()?;
    log(&format!("rdns database built in {:.1?}", started.elapsed()));
    Ok(())
}

fn parse_ip(text: &[u8]) -> u32 {
    let text = std::str::from_utf8(text).expect("utf8 address");
    text.parse::<Ipv4Addr>().expect("ipv4 address").into()
}

fn records(input: impl BufRead) -> impl Iterator<Item = Record> {
    let mut lines = input.split(b'\n').map(|line| line.expect("read rdns dump"));
    let mut pending: Option<Record> = None;
    std::iter::from_fn(move || {
        for line in lines.by_ref() {
            let tab = line.iter().position(|&byte| byte == b'\t').expect("tab");
            let ip = parse_ip(&line[..tab]);
            let host = line[tab + 1..].to_vec();
            match &mut pending {
                Some(record) if record.ip == ip => record.hosts.push(host),
                _ => {
                    let next = Record { ip, hosts: vec![host] };
                    if let Some(done) = pending.replace(next) {
                        return Some(done);
                    }
                }
            }
        }
        pending.take()
    })
}

fn choose(record: &Record, next: Option<&Record>) -> Vec<Vec<u8>> {
    let follower = |index| next.and_then(|next| Some((next.ip, next.hosts.get(index)?)));
    record
        .hosts
        .iter()
        .enumerate()
        .map(|(index, host)| {
            let follower = follower(index).map(|(ip, host)| (ip, host.as_slice()));
            template(record.ip, host, follower)
        })
        .collect()
}

fn matches(templates: &[Vec<u8>], record: &Record, buffer: &mut Vec<u8>) -> bool {
    templates.len() == record.hosts.len()
        && templates
            .iter()
            .zip(&record.hosts)
            .all(|(template, host)| renders(template, record.ip, host, buffer))
}

fn next_run(
    records: &mut Peekable<impl Iterator<Item = Record>>,
    buffer: &mut Vec<u8>,
) -> Option<Run> {
    let record = records.next()?;
    let templates = choose(&record, records.peek());
    assert!(matches(&templates, &record, buffer), "bad template at {}", record.ip);
    let mut run = Run { start: record.ip, end: record.ip, template: Vec::new() };
    while let Some(next) = records.peek()
        && run.end.checked_add(1) == Some(next.ip)
        && matches(&templates, next, buffer)
    {
        run.end = next.ip;
        records.next();
    }
    run.template = templates.join(&SEPARATOR);
    Some(run)
}

fn encode_block(runs: &[Run]) -> Vec<u8> {
    let mut out = Vec::new();
    push_varint(&mut out, runs.len() as u32);
    let mut next = runs[0].start;
    for run in runs {
        push_varint(&mut out, run.start - next);
        next = run.end.wrapping_add(1);
    }
    for run in runs {
        push_varint(&mut out, run.end - run.start);
    }
    let templates: Vec<&[u8]> = runs.iter().map(|run| run.template.as_slice()).collect();
    out.extend(templates.join(&0));
    assert!(out.len() <= WINDOW as usize, "rdns block too large");
    out
}

fn compress(data: &[u8]) -> Vec<u8> {
    lzma(data, LZMA_SETTINGS, 9 | PRESET_EXTREME, WINDOW)
}

impl Packed {
    fn flush(&mut self, blocks: &mut Vec<Vec<Run>>) {
        let compressed: Vec<Vec<u8>> =
            blocks.par_iter().map(|block| compress(&encode_block(block))).collect();
        for (block, data) in blocks.iter().zip(compressed) {
            self.data.extend(data);
            self.index.extend(block[0].start.to_le_bytes());
            self.index.extend((self.data.len() as u32).to_le_bytes());
            self.blocks += 1;
            self.runs += block.len();
        }
        blocks.clear();
    }

    fn write(&self, path: &str) -> io::Result<()> {
        let mut out = BufWriter::new(File::create(path)?);
        out.write_all(MAGIC)?;
        out.write_all(&self.blocks.to_le_bytes())?;
        out.write_all(&self.index)?;
        out.write_all(&self.data)?;
        out.flush()
    }
}

fn pack() -> io::Result<()> {
    let input = BufReader::new(XzDecoder::new(File::open(DUMP)?));
    let mut records = records(input).peekable();
    let mut buffer = Vec::new();
    let mut packed = Packed::default();
    let mut blocks: Vec<Vec<Run>> = Vec::new();
    let mut block: Vec<Run> = Vec::new();
    let mut bytes = 0;
    while let Some(run) = next_run(&mut records, &mut buffer) {
        bytes += run.template.len() + 3;
        block.push(run);
        if bytes > BLOCK_BYTES {
            blocks.push(std::mem::take(&mut block));
            bytes = 0;
        }
        if blocks.len() == BATCH_BLOCKS {
            packed.flush(&mut blocks);
        }
    }
    if !block.is_empty() {
        blocks.push(block);
    }
    packed.flush(&mut blocks);
    fs::create_dir_all("dist")?;
    packed.write(OUTPUT)?;
    let size = 8 + packed.index.len() + packed.data.len();
    log(&format!("{} runs in {} blocks, {size} bytes", packed.runs, packed.blocks));
    Ok(())
}
