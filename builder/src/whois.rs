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
        let found = self.attributes.iter().find(|(name, _)| name == key);
        found.map(|(_, value)| value.as_str()).filter(|value| !value.is_empty())
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

pub fn organisations(paths: &[&Path]) -> HashMap<String, String> {
    let mut names = HashMap::new();
    for path in paths {
        blocks(path, |attributes| {
            let get = |key: &str| attributes.iter().find(|(name, _)| name == key);
            if let (Some((_, id)), Some((_, name))) =
                (get("organisation"), get("org-name"))
            {
                names.insert(id.clone(), name.clone());
            }
        });
    }
    names
}
