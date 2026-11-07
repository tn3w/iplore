use std::collections::{HashMap, HashSet};

use serde::Deserialize;

use crate::load_json;

const MAX_TEXT_CHARS: usize = 128;

#[derive(Deserialize)]
pub struct Patterns {
    pub address: String,
    pub asn: String,
    pub whois_geofeed_url: String,
    pub geofeed_line: String,
    pub geofeed_reference: String,
}

#[derive(Deserialize)]
struct TextRules {
    folding: HashMap<String, String>,
    needle_minimum_length: usize,
    placeholders: HashSet<String>,
    placeholder_domains: HashSet<String>,
    junk_markers: Vec<String>,
    question_mark_share: f64,
    street_words: HashSet<String>,
    street_leaders: Vec<String>,
    patterns: Patterns,
}

pub struct Text {
    rules: TextRules,
    folding: HashMap<char, String>,
}

impl Text {
    pub fn load() -> Text {
        let rules: TextRules = load_json("text.json");
        let mut folding = HashMap::new();
        for (replacement, characters) in &rules.folding {
            for character in characters.chars() {
                folding.insert(character, replacement.clone());
                for upper in character.to_uppercase() {
                    folding.insert(upper, replacement.clone());
                }
            }
        }
        Text { rules, folding }
    }

    pub fn patterns(&self) -> &Patterns {
        &self.rules.patterns
    }

    pub fn fold(&self, text: &str) -> String {
        let mut output = String::with_capacity(text.len());
        for character in text.chars() {
            match self.folding.get(&character) {
                Some(replacement) => output.push_str(replacement),
                None if character.is_alphanumeric() => {
                    output.extend(character.to_lowercase())
                }
                None => output.push(' '),
            }
        }
        output.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    pub fn clean(&self, text: &str) -> Option<String> {
        let text = mend_double_encoding(text);
        let text: String = text
            .chars()
            .filter(|character| {
                let invisible = matches!(character, '\u{200b}'..='\u{200f}' | '\u{feff}');
                !invisible && (character.is_whitespace() || !character.is_control())
            })
            .map(|character| if character == '\u{a0}' { ' ' } else { character })
            .collect();
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let text: String = text.chars().take(MAX_TEXT_CHARS).collect();
        let text = text.trim_end_matches([',', ';', ':', '/', '-', '_', '|', ' ']).trim();
        let questions = text.chars().filter(|&character| character == '?').count();
        let share = questions as f64 / text.chars().count().max(1) as f64;
        let junk =
            self.rules.junk_markers.iter().any(|marker| text.contains(marker.as_str()));
        let zeros = text.chars().all(|character| character == '0' || character == ' ');
        let placeholder = self.rules.placeholders.contains(&text.to_lowercase());
        let rejected =
            junk || zeros || placeholder || share > self.rules.question_mark_share;
        (!text.is_empty() && !rejected).then(|| text.to_string())
    }

    pub fn company(&self, text: &str) -> Option<String> {
        let company = self.clean(text)?;
        let lower = company.to_lowercase();
        let leads_like_street = lower
            .starts_with(|character: char| character.is_ascii_digit())
            || self
                .rules
                .street_leaders
                .iter()
                .any(|leader| lower.starts_with(leader.as_str()));
        let has_street_word = lower
            .split(|character: char| !character.is_alphanumeric() && character != 'ß')
            .any(|word| self.rules.street_words.contains(word));
        (!(leads_like_street && has_street_word)).then_some(company)
    }

    pub fn website(&self, text: &str) -> Option<String> {
        let text = self.clean(text)?.to_lowercase();
        let text = text.split_once("://").map_or(text.as_str(), |(_, rest)| rest);
        let text = text.strip_prefix("www.").unwrap_or(text);
        let text = text.split(['?', '#', ' ']).next()?.trim_end_matches('/');
        let host = text.split(['/', ':']).next()?;
        let numeric =
            host.chars().all(|character| character.is_ascii_digit() || character == '.');
        let valid = host.contains('.')
            && !numeric
            && !self.rules.placeholder_domains.contains(host);
        valid.then(|| text.to_string())
    }

    pub fn mailbox(&self, text: &str) -> Option<String> {
        let text = self.clean(text)?.to_lowercase();
        let (local, domain) = text.split_once('@')?;
        let valid = !local.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && !text.contains(char::is_whitespace)
            && !self.rules.placeholder_domains.contains(domain);
        valid.then_some(text)
    }

    pub fn contains_word(&self, haystack_folded: &str, needle_folded: &str) -> bool {
        if needle_folded.len() < self.rules.needle_minimum_length {
            return false;
        }
        format!(" {haystack_folded} ").contains(&format!(" {needle_folded} "))
    }
}

pub fn decode_line(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => bytes.iter().map(|&byte| byte as char).collect(),
    }
}

fn mend_double_encoding(text: &str) -> String {
    if !text.contains(['Ã', 'Â']) {
        return text.to_string();
    }
    let bytes: Option<Vec<u8>> =
        text.chars().map(|character| u8::try_from(u32::from(character)).ok()).collect();
    bytes
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn text() -> Text {
        let rules = json!({
            "folding": {},
            "needle_minimum_length": 3,
            "placeholders": ["n/a"],
            "placeholder_domains": [],
            "junk_markers": [],
            "question_mark_share": 0.5,
            "street_words": [],
            "street_leaders": [],
            "patterns": {
                "address": "", "asn": "", "whois_geofeed_url": "",
                "geofeed_line": "", "geofeed_reference": "",
            },
        });
        Text { rules: serde_json::from_value(rules).unwrap(), folding: HashMap::new() }
    }

    #[test]
    fn clean_drops_control_characters_but_keeps_word_breaks() {
        let text = text();
        assert_eq!(
            text.clean("Acme\u{0}\u{1b}[31m Corp").as_deref(),
            Some("Acme[31m Corp")
        );
        assert_eq!(
            text.clean("Acme\tCorp\r\nLtd\u{85}Inc").as_deref(),
            Some("Acme Corp Ltd Inc")
        );
        assert_eq!(text.clean("\u{7f}\u{9b}\u{0}"), None);
    }

    #[test]
    fn clean_caps_length() {
        let text = text();
        let long = "word ".repeat(100);
        let cleaned = text.clean(&long).unwrap();
        assert!(cleaned.chars().count() <= MAX_TEXT_CHARS);
        assert!(cleaned.starts_with("word word"));
        assert!(!cleaned.ends_with(' '));
        let exact = "x".repeat(MAX_TEXT_CHARS);
        assert_eq!(text.clean(&exact).as_deref(), Some(exact.as_str()));
        assert_eq!(text.clean(&"é".repeat(300)).unwrap().chars().count(), MAX_TEXT_CHARS);
    }
}
