use reader::rdns::{
    BASE36, DECIMAL, END, HEX, PADDED, PLAIN, SELECTORS, SHORT_HEX, render, select,
};

const MAX_COMBINATIONS: usize = 256;

type Codes = Vec<u8>;

struct Span {
    start: usize,
    end: usize,
    options: Vec<Codes>,
}

pub fn renders(template: &[u8], ip: u32, host: &[u8], buffer: &mut Vec<u8>) -> bool {
    buffer.clear();
    render(template, ip, buffer);
    buffer == host
}

fn affine(code: u8, width: usize, offset: i64) -> Codes {
    let mut codes = vec![code, b'0' + width as u8];
    codes.extend(offset.to_string().bytes());
    codes.push(END);
    codes
}

fn replace_all(host: &[u8], needle: &[u8], codes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(host.len());
    let mut position = 0;
    while position < host.len() {
        if host[position..].starts_with(needle) {
            out.extend_from_slice(codes);
            position += needle.len();
            continue;
        }
        out.push(host[position]);
        position += 1;
    }
    out
}

fn substitute_whole(ip: u32, host: &[u8]) -> Vec<u8> {
    let [a, b, c, d] = ip.to_be_bytes();
    let patterns = [
        (format!("{a:02x}{b:02x}{c:02x}{d:02x}"), [HEX, HEX + 1, HEX + 2, HEX + 3]),
        (format!("{d:02x}{c:02x}{b:02x}{a:02x}"), [HEX + 3, HEX + 2, HEX + 1, HEX]),
        (
            format!("{a:03}{b:03}{c:03}{d:03}"),
            [PADDED, PADDED + 1, PADDED + 2, PADDED + 3],
        ),
        (
            format!("{d:03}{c:03}{b:03}{a:03}"),
            [PADDED + 3, PADDED + 2, PADDED + 1, PADDED],
        ),
        (format!("{a}{b}{c}{d}"), [PLAIN, PLAIN + 1, PLAIN + 2, PLAIN + 3]),
    ];
    let mut out = host.to_vec();
    for (needle, codes) in patterns {
        out = replace_all(&out, needle.as_bytes(), &codes);
    }
    out
}

fn octet_codes(
    text: &[u8],
    octets: [u8; 4],
    code: u8,
    format: fn(u8) -> String,
) -> Vec<Codes> {
    (0..4u8)
        .filter(|&index| text == format(octets[index as usize]).as_bytes())
        .map(|index| vec![code + index])
        .collect()
}

fn chunks(
    text: &[u8],
    width: usize,
    octets: [u8; 4],
    code: u8,
    format: fn(u8) -> String,
) -> Option<Codes> {
    if text.len() <= width || !text.len().is_multiple_of(width) {
        return None;
    }
    text.chunks(width)
        .map(|chunk| {
            octet_codes(chunk, octets, code, format).first().map(|codes| codes[0])
        })
        .collect()
}

fn decompose(text: &[u8], octets: [u8; 4]) -> Vec<Codes> {
    if text.is_empty() {
        return vec![Vec::new()];
    }
    let mut found = Vec::new();
    for (index, octet) in (0..4u8).zip(octets) {
        let mut pieces = vec![(octet.to_string(), PLAIN + index)];
        if octet < 100 {
            pieces.push((format!("{octet:03}"), PADDED + index));
        }
        for (piece, code) in pieces {
            let Some(rest) = text.strip_prefix(piece.as_bytes()) else {
                continue;
            };
            found.extend(
                decompose(rest, octets)
                    .into_iter()
                    .map(|tail| [vec![code], tail].concat()),
            );
        }
    }
    found.truncate(8);
    found
}

fn affine_options(
    text: &[u8],
    ip: u32,
    code: u8,
    parse: fn(&str) -> Option<i64>,
) -> Vec<Codes> {
    let value = std::str::from_utf8(text).ok().and_then(parse);
    let Some(value) = value else {
        return Vec::new();
    };
    let width = if text.len() > 1 && text[0] == b'0' { text.len() } else { 0 };
    (0..SELECTORS)
        .map(|selector| affine(code + selector, width, value - select(ip, selector)))
        .collect()
}

fn decimal_options(text: &[u8], ip: u32) -> Vec<Codes> {
    let octets = ip.to_be_bytes();
    let mut options = octet_codes(text, octets, PLAIN, |octet| octet.to_string());
    options.extend(octet_codes(text, octets, PADDED, |octet| format!("{octet:03}")));
    if text.len() > 12 {
        return options;
    }
    options.extend(decompose(text, octets).into_iter().filter(|codes| codes.len() > 1));
    options.extend(affine_options(text, ip, DECIMAL, |text| text.parse().ok()));
    if text.len() > 3 {
        let (prefix, suffix) = text.split_at(text.len() - 3);
        let padded = octet_codes(suffix, octets, PADDED, |octet| format!("{octet:03}"));
        for tail in padded {
            for head in affine_options(prefix, ip, DECIMAL, |text| text.parse().ok()) {
                options.push([head, tail.clone()].concat());
            }
        }
    }
    options
}

fn hex_options(text: &[u8], ip: u32) -> Vec<Codes> {
    let octets = ip.to_be_bytes();
    let mut options = octet_codes(text, octets, HEX, |octet| format!("{octet:02x}"));
    options.extend(octet_codes(text, octets, SHORT_HEX, |octet| format!("{octet:x}")));
    options.extend(chunks(text, 2, octets, HEX, |octet| format!("{octet:02x}")));
    options
}

fn base36_options(text: &[u8], ip: u32) -> Vec<Codes> {
    let parse = |text: &str| i64::from_str_radix(text, 36).ok();
    affine_options(text, ip, BASE36, parse)
}

fn digit_runs(token: &[u8]) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let mut position = 0;
    while position < token.len() {
        let digits =
            token[position..].iter().take_while(|byte| byte.is_ascii_digit()).count();
        if digits > 0 {
            runs.push((position, position + digits));
        }
        position += digits.max(1);
    }
    runs
}

fn is_hex(token: &[u8]) -> bool {
    token.iter().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn options(token: &[u8], ip: u32) -> Vec<Codes> {
    let runs = digit_runs(token);
    if runs == [(0, token.len())] {
        return [decimal_options(token, ip), hex_options(token, ip)].concat();
    }
    let mut options = if is_hex(token) { hex_options(token, ip) } else { Vec::new() };
    for (start, end) in runs {
        for codes in decimal_options(&token[start..end], ip) {
            options.push([&token[..start], &codes, &token[end..]].concat());
        }
    }
    if token.len() <= 6 {
        options.extend(base36_options(token, ip));
    }
    options
}

fn bounds(base: &[u8]) -> Vec<(usize, usize)> {
    let mut bounds = Vec::new();
    let mut position = 0;
    while position < base.len() {
        let length = base[position..]
            .iter()
            .take_while(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            .count();
        let token = &base[position..position + length];
        let runs = digit_runs(token);
        if length == 0 {
            position += 1;
            continue;
        }
        if runs.len() <= 1 || is_hex(token) {
            bounds.push((position, position + length));
        } else {
            bounds.extend(
                runs.iter().map(|&(start, end)| (position + start, position + end)),
            );
        }
        position += length;
    }
    bounds
}

fn spans(base: &[u8], ip: u32) -> Vec<Span> {
    bounds(base)
        .into_iter()
        .map(|(start, end)| Span { start, end, options: options(&base[start..end], ip) })
        .collect()
}

fn is_octet(codes: &Codes) -> bool {
    !codes.iter().any(|code| (DECIMAL..END).contains(code))
}

fn score(choice: &[Option<&Codes>]) -> usize {
    let codes: Vec<u8> = choice
        .iter()
        .flatten()
        .flat_map(|codes| codes.iter().copied())
        .filter(|&code| code < END)
        .collect();
    let adjacent = codes
        .windows(2)
        .filter(|pair| {
            (pair[0] - 1) / 4 == (pair[1] - 1) / 4 && pair[0].abs_diff(pair[1]) == 1
        })
        .count();
    let padded = codes.iter().any(|code| (PADDED..HEX).contains(code));
    codes.len() * 8 + adjacent * 2 + usize::from(padded)
}

fn default_choice(spans: &[Span]) -> Vec<Option<&Codes>> {
    let mut combinations = vec![Vec::new()];
    for span in spans {
        let choices = span.options.iter().filter(|codes| is_octet(codes)).map(Some);
        let choices: Vec<Option<&Codes>> = choices.chain([None]).collect();
        combinations = combinations
            .iter()
            .flat_map(|combination| {
                choices
                    .iter()
                    .map(move |&choice| [combination.clone(), vec![choice]].concat())
            })
            .take(MAX_COMBINATIONS)
            .collect();
    }
    combinations.into_iter().max_by_key(|choice| score(choice)).unwrap_or_default()
}

fn skeleton(base: &[u8], spans: &[(usize, usize)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut position = 0;
    for &(start, end) in spans {
        out.extend_from_slice(&base[position..start]);
        out.push(0);
        position = end;
    }
    out.extend_from_slice(&base[position..]);
    out
}

fn refine<'a>(
    choice: &mut [Option<&'a Codes>],
    spans: &'a [Span],
    base: &[u8],
    next: (u32, &[u8]),
) {
    let (next_ip, next_host) = next;
    let next_base = substitute_whole(next_ip, next_host);
    let next_bounds = bounds(&next_base);
    if skeleton(base, &bounds(base)) != skeleton(&next_base, &next_bounds) {
        return;
    }
    let mut buffer = Vec::new();
    for ((span, (start, end)), chosen) in spans.iter().zip(next_bounds).zip(choice) {
        let target = &next_base[start..end];
        let literal = &base[span.start..span.end];
        let mut fits = |codes: &Codes| renders(codes, next_ip, target, &mut buffer);
        if chosen.is_some_and(&mut fits) {
            continue;
        }
        *chosen = match literal == target {
            true => None,
            false => span.options.iter().find(|codes| fits(codes)),
        };
    }
}

pub fn template(ip: u32, host: &[u8], next: Option<(u32, &[u8])>) -> Vec<u8> {
    let base = substitute_whole(ip, host);
    let spans = spans(&base, ip);
    let mut choice = default_choice(&spans);
    if let Some(next) = next {
        refine(&mut choice, &spans, &base, next);
    }

    let mut template = Vec::with_capacity(base.len());
    let mut position = 0;
    for (span, chosen) in spans.iter().zip(choice) {
        template.extend_from_slice(&base[position..span.start]);
        match chosen {
            Some(codes) => template.extend_from_slice(codes),
            None => template.extend_from_slice(&base[span.start..span.end]),
        }
        position = span.end;
    }
    template.extend_from_slice(&base[position..]);
    template
}
