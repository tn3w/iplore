use std::net::{IpAddr, Ipv6Addr};

pub type Address = u128;

#[derive(Clone, Debug)]
pub struct Span<T> {
    pub first: Address,
    pub last: Address,
    pub value: T,
}

pub type Families<T> = [Vec<Span<T>>; 2];

pub fn slot(family: usize) -> usize {
    usize::from(family == 6)
}

pub fn bits(family: usize) -> u32 {
    if family == 4 { 32 } else { 128 }
}

pub fn from_ip(address: IpAddr) -> (usize, Address) {
    match address {
        IpAddr::V4(v4) => (4, u32::from(v4) as Address),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => (4, u32::from(v4) as Address),
            None => (6, u128::from(v6)),
        },
    }
}

pub fn to_ip(family: usize, address: Address) -> IpAddr {
    if family == 4 {
        IpAddr::V4((address as u32).into())
    } else {
        IpAddr::V6(Ipv6Addr::from(address))
    }
}

pub fn parse_address(text: &str) -> Option<(usize, Address)> {
    text.trim().parse::<IpAddr>().ok().map(from_ip)
}

pub fn prefix_range(family: usize, address: Address, length: u32) -> (Address, Address) {
    let host_bits = bits(family) - length.min(bits(family));
    let mask = if host_bits >= 128 { Address::MAX } else { (1 << host_bits) - 1 };
    (address & !mask, address | mask)
}

pub fn parse_range(text: &str) -> Option<(usize, Address, Address)> {
    let text = text.trim();
    if let Some((first, last)) = text.split_once(['-', ',']) {
        let (family, first) = parse_address(first)?;
        let (other, last) = parse_address(last)?;
        return (family == other && first <= last).then_some((family, first, last));
    }
    let Some((address, length)) = text.split_once('/') else {
        let (family, address) = parse_address(text)?;
        return Some((family, address, address));
    };
    let mapped = address.contains(':');
    let (family, address) = parse_address(address)?;
    let mut length: u32 = length.trim().parse().ok()?;
    if family == 4 && mapped {
        length = length.checked_sub(96)?;
    }
    if length > bits(family) {
        return None;
    }
    let (first, last) = prefix_range(family, address, length);
    Some((family, first, last))
}

pub fn prefix_length(family: usize, first: Address, last: Address) -> Option<u32> {
    let size = last.wrapping_sub(first).wrapping_add(1);
    let aligned = size == 0 || (size.is_power_of_two() && first.is_multiple_of(size));
    if !aligned {
        return None;
    }
    let host_bits = if size == 0 { 128 } else { size.trailing_zeros() };
    Some(bits(family) - host_bits)
}

pub fn aligned_blocks(
    family: usize,
    first: Address,
    last: Address,
) -> Vec<(Address, u32)> {
    let mut blocks = Vec::new();
    let mut start = first;
    loop {
        let mut host_bits =
            if start == 0 { bits(family) } else { start.trailing_zeros() };
        host_bits = host_bits.min(bits(family));
        while host_bits > 0 && block_end(start, host_bits) > last {
            host_bits -= 1;
        }
        blocks.push((start, bits(family) - host_bits));
        let end = block_end(start, host_bits);
        if end >= last {
            return blocks;
        }
        start = end + 1;
    }
}

fn block_end(start: Address, host_bits: u32) -> Address {
    if host_bits >= 128 { Address::MAX } else { start | ((1 << host_bits) - 1) }
}

pub fn sweep(
    spans: &[(Address, Address)],
    mut emit: impl FnMut(Address, Address, &[usize]),
) {
    let mut events: Vec<(Address, bool, usize)> = Vec::with_capacity(spans.len() * 2);
    for (index, &(first, last)) in spans.iter().enumerate() {
        events.push((first, true, index));
        if let Some(after) = last.checked_add(1) {
            events.push((after, false, index));
        }
    }
    events.sort_unstable_by_key(|&(position, opens, _)| (position, opens));
    let mut active: Vec<usize> = Vec::new();
    let mut cursor = 0;
    while cursor < events.len() {
        let position = events[cursor].0;
        while cursor < events.len() && events[cursor].0 == position {
            let (_, opens, index) = events[cursor];
            if opens {
                active.push(index);
            } else if let Some(found) = active.iter().position(|&open| open == index) {
                active.swap_remove(found);
            }
            cursor += 1;
        }
        if active.is_empty() {
            continue;
        }
        let end = events.get(cursor).map_or(Address::MAX, |event| event.0 - 1);
        emit(position, end, &active);
    }
}

pub fn pick<T, K: Ord>(
    spans: &[Span<T>],
    key: impl Fn(&Span<T>) -> K,
) -> Vec<Span<usize>> {
    let ranges: Vec<(Address, Address)> =
        spans.iter().map(|span| (span.first, span.last)).collect();
    let mut output: Vec<Span<usize>> = Vec::new();
    sweep(&ranges, |first, last, active| {
        let winner = active.iter().min_by_key(|&&index| (key(&spans[index]), index));
        push_merged(&mut output, first, last, *winner.expect("active"));
    });
    output
}

pub fn narrowest<T: Clone + PartialEq>(spans: &[Span<T>]) -> Vec<Span<T>> {
    let mut output = Vec::new();
    for span in pick(spans, |span| span.last - span.first) {
        push_merged(&mut output, span.first, span.last, spans[span.value].value.clone());
    }
    output
}

pub fn push_merged<T: PartialEq>(
    output: &mut Vec<Span<T>>,
    first: Address,
    last: Address,
    value: T,
) {
    if let Some(previous) = output.last_mut()
        && previous.value == value
        && previous.last.checked_add(1) == Some(first)
    {
        previous.last = last;
        return;
    }
    output.push(Span { first, last, value });
}

pub fn lookup<T>(spans: &[Span<T>], address: Address) -> Option<&T> {
    let index = spans.partition_point(|span| span.first <= address).checked_sub(1)?;
    let span = &spans[index];
    (span.last >= address).then_some(&span.value)
}

pub fn split_families<T>(rows: Vec<(usize, Span<T>)>) -> Families<T> {
    let mut families: Families<T> = [Vec::new(), Vec::new()];
    for (family, span) in rows {
        families[slot(family)].push(span);
    }
    families
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges() {
        assert_eq!(parse_range("10.0.0.0/8"), Some((4, 0x0a00_0000, 0x0aff_ffff)));
        assert_eq!(parse_range("1.2.3.4 - 1.2.3.9"), Some((4, 0x0102_0304, 0x0102_0309)));
        assert_eq!(
            parse_range("::ffff:1.2.3.0/120"),
            Some((4, 0x0102_0300, 0x0102_03ff))
        );
        assert_eq!(parse_range("2001:db8::/32").map(|range| range.0), Some(6));
        assert_eq!(parse_range("1.2.3.4/33"), None);
    }

    #[test]
    fn splits_into_aligned_blocks() {
        let blocks = aligned_blocks(4, 0x0a00_0001, 0x0a00_0006);
        assert_eq!(
            blocks,
            vec![
                (0x0a00_0001, 32),
                (0x0a00_0002, 31),
                (0x0a00_0004, 31),
                (0x0a00_0006, 32)
            ]
        );
        assert_eq!(aligned_blocks(4, 0, u32::MAX as Address), vec![(0, 0)]);
    }

    #[test]
    fn narrowest_span_wins() {
        let spans = vec![
            Span { first: 0, last: 255, value: 'a' },
            Span { first: 16, last: 31, value: 'b' },
        ];
        let picked: Vec<(Address, Address, char)> = narrowest(&spans)
            .iter()
            .map(|span| (span.first, span.last, span.value))
            .collect();
        assert_eq!(picked, vec![(0, 15, 'a'), (16, 31, 'b'), (32, 255, 'a')]);
    }

    #[test]
    fn measures_prefix_length() {
        assert_eq!(prefix_length(4, 0x0a00_0000, 0x0a00_00ff), Some(24));
        assert_eq!(prefix_length(4, 0x0a00_0001, 0x0a00_00ff), None);
    }
}
