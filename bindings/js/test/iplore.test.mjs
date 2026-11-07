import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { DatabaseError, open } from "../dist/index.js";

const here = (path) => fileURLToPath(new URL(path, import.meta.url));
const dataDirectory = process.env.IPLORE_DATA ?? here("../../data");
const cli = process.env.IPLORE_CLI ?? here("../../../target/release/iplore");
const file = (name) => `${dataDirectory}/iplore-${name}.ipl`;
const load = (name) => open(readFileSync(file(name)));
const native = (name, address) =>
  JSON.parse(execFileSync(cli, [file(name), address], { encoding: "utf8" }));

const addresses = JSON.parse(readFileSync(here("../../../reader/tests/addresses.json")));

const known = [
  "1.1.1.1",
  "8.8.8.8",
  "185.220.101.1",
  "66.249.66.1",
  "172.224.226.1",
  "98.97.0.1",
  "2606:4700:4700::1111",
  "2001:4860:4860::8888",
];

function randomAddresses(count) {
  let state = 0x9e3779b9;
  const next = () => (state = (Math.imul(state, 1664525) + 1013904223) >>> 0);
  const word = () => next().toString(16).padStart(8, "0");
  return Array.from({ length: count }, (_, index) => {
    if (index % 4 < 3) return [24, 16, 8, 0].map((s) => (next() >>> s) & 255).join(".");
    const digits = "2" + (word() + word() + word() + word()).slice(1);
    return digits.match(/.{4}/g).join(":");
  });
}

test("full database knows Cloudflare", async () => {
  const answer = (await load("full")).lookup("1.1.1.1");
  assert.equal(answer.place?.country?.code, "AU");
  assert.equal(answer.network.asn, 13335);
  assert.match(answer.network.operator.company, /Cloudflare/);
  assert.deepEqual(answer.abuse.flags, ["anycast"]);
});

test("IPv6 lookup", async () => {
  const answer = (await load("full")).lookup("2606:4700:4700::1111");
  assert.equal(answer.network.asn, 13335);
});

test("anonymizer flags Tor exits", async () => {
  const answer = (await load("anonymizer")).lookup("185.220.101.1");
  assert.equal(answer.abuse.service, "tor_exit_node");
});

test("country database answers only the country", async () => {
  const answer = (await load("country")).lookup("1.1.1.1");
  assert.equal(answer.place?.country?.code, "AU");
  assert.equal(answer.network, null);
});

test("reserved space answers null everywhere", async () => {
  const answer = (await load("full")).lookup("10.0.0.1");
  assert.deepEqual(answer, { place: null, network: null, abuse: null });
});

test("address grammar matches the shared cases", async () => {
  const database = await load("full");
  for (const [input, canonical] of Object.entries(addresses.valid)) {
    assert.deepEqual(database.lookup(input), database.lookup(canonical), input);
  }
  for (const input of addresses.invalid) {
    assert.throws(() => database.lookup(input), TypeError, JSON.stringify(input));
  }
});

test("non-string address throws TypeError", async () => {
  const database = await load("country");
  for (const address of [undefined, null, 1, {}, ["1.1.1.1"]]) {
    assert.throws(() => database.lookup(address), TypeError);
  }
});

test("corrupt file throws DatabaseError, not TypeError", async () => {
  const bytes = readFileSync(file("country"));
  const cases = [new Uint8Array(0), new Uint8Array(64), bytes.subarray(0, 100)];
  cases.push(bytes.subarray(0, bytes.length - 1), bytes.subarray(0, 12 + 30000));
  for (const corrupt of cases) {
    await assert.rejects(open(corrupt), (error) => {
      assert.ok(error instanceof DatabaseError);
      assert.ok(!(error instanceof TypeError));
      return true;
    });
  }
  await assert.rejects(open(new Uint8Array(64)), /not an iplore v1 file/);
});

test("corrupt blocks throw DatabaseError on lookup", async () => {
  const bytes = Uint8Array.from(readFileSync(file("country")));
  const header = new DataView(bytes.buffer).getUint32(8, true);
  const start = 12 + header;
  for (let position = start; position < bytes.length; position += 1500) {
    bytes[position] ^= 0xff;
  }
  const database = await open(bytes);
  assert.throws(() => database.lookup("1.1.1.1"), DatabaseError);
  assert.throws(() => database.lookup("nope"), TypeError);
});

test("accepts Response, ArrayBuffer and every ArrayBufferView", async () => {
  const bytes = readFileSync(file("country"));
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length);
  const expected = (await load("country")).lookup("1.1.1.1");
  const padded = new Uint8Array(bytes.length + 7);
  padded.set(bytes, 3);
  const sources = [
    buffer,
    new Response(bytes),
    new Uint8Array(buffer),
    new DataView(buffer),
    new Int8Array(buffer),
    padded.subarray(3, 3 + bytes.length),
    new DataView(padded.buffer, 3, bytes.length),
  ];
  for (const source of sources) {
    assert.deepEqual((await open(source)).lookup("1.1.1.1"), expected);
  }
  await assert.rejects(open(new Response("", { status: 404 })), /404/);
});

test("rejects unsupported sources", async () => {
  for (const source of ["path.ipl", null, undefined, 42, {}, new Blob(["x"]).stream()]) {
    await assert.rejects(open(source), TypeError);
  }
});

test("rejects oversized databases before allocating", async () => {
  await assert.rejects(open(new ArrayBuffer(2 ** 30 + 1)), DatabaseError);
});

test("default module load failure is retried", async () => {
  const directory = mkdtempSync(`${tmpdir()}/iplore-`);
  copyFileSync(here("../dist/index.js"), `${directory}/index.js`);
  const copy = await import(pathToFileURL(`${directory}/index.js`));
  const bytes = readFileSync(file("country"));
  await assert.rejects(copy.open(bytes));
  copyFileSync(here("../dist/iplore.wasm"), `${directory}/iplore.wasm`);
  assert.equal((await copy.open(bytes)).lookup("1.1.1.1").place.country.code, "AU");
});

const wasmModule = () => {
  const code = (body) => [body.length + 2, 0, ...body, 0x0b];
  const constant = code([0x41, 0]);
  const trap = code([0x00]);
  const name = (text) => [text.length, ...Buffer.from(text)];
  const exports = [
    [name("memory"), 2, 0],
    [name("allocate"), 0, 0],
    [name("output"), 0, 1],
    [name("output_length"), 0, 2],
    [name("load"), 0, 3],
    [name("lookup"), 0, 4],
    [name("about"), 0, 5],
  ].flat(2);
  const section = (id, ...content) => [id, content.flat().length, ...content.flat()];
  return new WebAssembly.Module(
    new Uint8Array([
      0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
      ...section(
        1,
        3,
        [0x60, 0, 1, 0x7f],
        [0x60, 1, 0x7f, 1, 0x7f],
        [0x60, 2, 0x7f, 0x7f, 1, 0x7f],
      ),
      ...section(3, 6, 1, 0, 0, 2, 2, 0),
      ...section(5, 1, 0, 1),
      ...section(7, 7, exports),
      ...section(10, 6, constant, constant, constant, constant, trap, trap),
    ]),
  );
};

test("a WebAssembly trap marks the instance unusable", async () => {
  const database = await open(new Uint8Array(8), wasmModule());
  assert.throws(() => database.lookup("1.1.1.1"), /WebAssembly trap/);
  for (const call of [() => database.lookup("1.1.1.1"), () => database.about()]) {
    assert.throws(call, (error) => {
      assert.ok(error instanceof DatabaseError);
      return /unusable/.test(error.message);
    });
  }
});

test("databases are independent", async () => {
  const [country, anonymizer] = await Promise.all([load("country"), load("anonymizer")]);
  assert.equal(country.lookup("185.220.101.1").abuse, null);
  assert.equal(anonymizer.lookup("185.220.101.1").abuse.service, "tor_exit_node");
});

test("about lists fields and sources", async () => {
  const about = (await load("country")).about();
  assert.ok(about.fields.some((field) => field.name === "place.country.code"));
  assert.ok(about.sections.every((section) => !("offsets" in section)));
});

const samples = { full: 100, place: 20, anonymizer: 20, traffic: 20 };

for (const [name, count] of Object.entries(samples)) {
  test(`${name} matches the native CLI`, async () => {
    const database = await load(name);
    for (const address of [...known, ...randomAddresses(count)]) {
      assert.deepEqual(database.lookup(address), native(name, address), address);
    }
  });
}
