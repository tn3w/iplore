use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use reader::{Error, Reader};

const ADDRESSES: [&str; 4] = ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::1"];

fn database() -> Option<Vec<u8>> {
    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../bindings/data/iplore-country.ipl");
    let bytes = std::fs::read(path).ok();
    if bytes.is_none() {
        eprintln!("skipped: {path} is missing");
    }
    bytes
}

fn within_time_limit(work: impl FnOnce() + Send + 'static) {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        work();
        sender.send(()).unwrap();
    });
    let finished = receiver.recv_timeout(Duration::from_secs(300));
    assert!(finished.is_ok(), "mutation run hung or panicked");
    handle.join().expect("mutation run panicked");
}

fn exercise(bytes: Vec<u8>) -> Result<(), Error> {
    let reader = Reader::from_bytes(bytes)?;
    for address in ADDRESSES {
        reader.lookup(address)?;
    }
    Ok(())
}

fn positions(length: usize, header_end: usize) -> Vec<usize> {
    let header = (0..header_end).step_by(37);
    let data = (header_end..length).step_by(((length - header_end) / 200).max(1));
    header.chain(data).chain([length - 1]).collect()
}

fn header_end(bytes: &[u8]) -> usize {
    12 + u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize
}

#[test]
fn intact_database_works() {
    let Some(bytes) = database() else { return };
    assert!(exercise(bytes).is_ok());
}

#[test]
fn every_truncation_is_an_error() {
    let Some(bytes) = database() else { return };
    within_time_limit(move || {
        let mut cuts = vec![0, 1, 7, 8, 11, 12, 13];
        cuts.extend(positions(bytes.len(), header_end(&bytes)));
        for cut in cuts.into_iter().filter(|&cut| cut < bytes.len()) {
            let result = Reader::from_bytes(bytes[..cut].to_vec());
            assert!(result.is_err(), "truncated at {cut}");
        }
    });
}

#[test]
fn wrong_header_lengths_are_errors() {
    let Some(bytes) = database() else { return };
    within_time_limit(move || {
        let real = header_end(&bytes) - 12;
        let wrong = [0, 1, 2, real - 1, real + 1, real + 1000, 0x7fff_ffff];
        let wrong = wrong.map(|length| length as u32);
        for length in wrong.into_iter().chain([0x8000_0000, u32::MAX]) {
            let mut changed = bytes.clone();
            changed[8..12].copy_from_slice(&length.to_le_bytes());
            assert!(Reader::from_bytes(changed).is_err(), "length {length}");
        }
    });
}

#[test]
fn flipped_bytes_never_panic_or_hang() {
    let Some(bytes) = database() else { return };
    within_time_limit(move || {
        let end = header_end(&bytes);
        let mut outcomes = [0usize; 2];
        for position in positions(bytes.len(), end) {
            for mask in [0x01, 0x80, 0xff] {
                let mut changed = bytes.clone();
                changed[position] ^= mask;
                outcomes[usize::from(exercise(changed).is_ok())] += 1;
            }
        }
        assert!(outcomes[0] > 0, "no corruption was detected");
    });
}

#[test]
fn garbage_and_random_data_are_errors() {
    for length in [0, 1, 11, 12, 64, 4096] {
        assert!(Reader::from_bytes(vec![0; length]).is_err());
        assert!(Reader::from_bytes(vec![0xff; length]).is_err());
    }
    let mut prefixed = b"IPLORE\0\x01".to_vec();
    prefixed.extend_from_slice(&[0xff; 4096]);
    assert!(Reader::from_bytes(prefixed).is_err());
}
