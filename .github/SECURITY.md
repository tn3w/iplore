# Security policy

## Reporting

Report vulnerabilities privately through
[GitHub security advisories](https://github.com/tn3w/iplore/security/advisories/new).
Do not open public issues for them. Expect a first reply within a week.

## Supported versions

Only the latest release and the current `master` receive fixes.

## Scope

In scope: the reader (Rust, WASM, JavaScript, Python, Go), the builder, the CLI and the
release workflows, including crashes, hangs or memory blowups on corrupt databases.

Databases are built from third-party feeds. Wrong, stale or poisoned feed data is a data
quality issue, not a vulnerability: do not rely on an answer as the only security
control. Verify downloads with `sha256sum -c SHA256SUMS` or
`gh attestation verify <file> -R tn3w/iplore`.
