use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::spans::{Address, parse_range};
use crate::text::decode_line;

pub struct WhoisObject {
    pub family: usize,
    pub first: Address,
    pub last: Address,
    pub attributes: Vec<(String, String)>,
}

impl WhoisObject {
    pub fn get(&self, key: &str) -> Option<&str> {
        value(&self.attributes, key)
    }
}

pub fn blocks(path: &Path, mut visit: impl FnMut(Vec<(String, String)>)) {
    let bytes = fs::read(path).unwrap_or_default();
    let mut attributes = Vec::new();
    for line in bytes.split(|&byte| byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            if !attributes.is_empty() {
                visit(std::mem::take(&mut attributes));
            }
            continue;
        }
        let line = decode_line(line);
        if let Some((key, value)) = line.split_once(':') {
            attributes.push((key.trim().to_lowercase(), value.trim().to_string()));
        }
    }
    if !attributes.is_empty() {
        visit(attributes);
    }
}

pub fn range_objects<T>(
    path: &Path,
    mut keep: impl FnMut(WhoisObject) -> Option<T>,
) -> Vec<T> {
    let mut objects = Vec::new();
    blocks(path, |attributes| {
        let Some((_, range)) = attributes.first() else {
            return;
        };
        if !matches!(attributes[0].0.as_str(), "inetnum" | "inet6num") {
            return;
        }
        let Some((family, first, last)) = parse_range(range) else {
            return;
        };
        objects.extend(keep(WhoisObject { family, first, last, attributes }));
    });
    objects
}

fn value<'a>(attributes: &'a [(String, String)], key: &str) -> Option<&'a str> {
    let found = attributes.iter().find(|(name, _)| name == key);
    found.map(|(_, value)| value.as_str()).filter(|value| !value.is_empty())
}

pub fn organisations(paths: &[&Path]) -> HashMap<String, String> {
    let mut names = HashMap::new();
    for path in paths {
        blocks(path, |attributes| {
            if let (Some(id), Some(name)) =
                (value(&attributes, "organisation"), value(&attributes, "org-name"))
            {
                names.insert(id.to_string(), name.to_string());
            }
        });
    }
    names
}

pub struct AbuseMailboxes {
    pub organisations: HashMap<String, String>,
    pub asns: HashMap<u32, String>,
}

pub fn abuse_mailboxes(
    roles: &Path,
    organisations: &[&Path],
    aut_nums: &Path,
) -> AbuseMailboxes {
    let mut handles: HashMap<String, String> = HashMap::new();
    blocks(roles, |attributes| {
        if let (Some(handle), Some(mailbox)) =
            (value(&attributes, "nic-hdl"), value(&attributes, "abuse-mailbox"))
        {
            handles.insert(handle.to_string(), mailbox.to_string());
        }
    });
    let mut by_organisation = HashMap::new();
    for path in organisations {
        blocks(path, |attributes| {
            let mailbox =
                value(&attributes, "abuse-c").and_then(|handle| handles.get(handle));
            if let (Some(id), Some(mailbox)) =
                (value(&attributes, "organisation"), mailbox)
            {
                by_organisation.insert(id.to_string(), mailbox.clone());
            }
        });
    }
    let mut asns = HashMap::new();
    blocks(aut_nums, |attributes| {
        let asn = value(&attributes, "aut-num")
            .and_then(|asn| asn.trim_start_matches("AS").parse::<u32>().ok());
        let mailbox = value(&attributes, "abuse-c")
            .and_then(|handle| handles.get(handle))
            .or_else(|| by_organisation.get(value(&attributes, "org")?));
        if let (Some(asn), Some(mailbox)) = (asn, mailbox) {
            asns.insert(asn, mailbox.clone());
        }
    });
    AbuseMailboxes { organisations: by_organisation, asns }
}
