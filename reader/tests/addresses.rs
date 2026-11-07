use std::collections::BTreeMap;

use reader::parse_address;
use serde::Deserialize;

#[derive(Deserialize)]
struct Cases {
    valid: BTreeMap<String, String>,
    invalid: Vec<String>,
}

fn cases() -> Cases {
    serde_json::from_str(include_str!("addresses.json")).unwrap()
}

#[test]
fn valid_addresses_parse_to_canonical_form() {
    for (input, canonical) in cases().valid {
        let parsed = parse_address(&input).map(|address| address.to_string());
        assert_eq!(parsed, Some(canonical), "{input:?}");
    }
}

#[test]
fn invalid_addresses_are_rejected() {
    for input in cases().invalid {
        assert_eq!(parse_address(&input), None, "{input:?}");
    }
}
