import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Miniflare } from "miniflare";

const here = (path) => fileURLToPath(new URL(path, import.meta.url));
const dataDirectory = process.env.IPLORE_DATA ?? here("../../data");
const cli = process.env.IPLORE_CLI ?? here("../../../target/release/iplore");
const databases = ["country", "anonymizer"];
const addresses = ["1.1.1.1", "185.220.101.1", "10.0.0.1", "2606:4700:4700::1111"];

const worker = `
import { open } from "./iplore.js";
import wasm from "./iplore.wasm";
import country from "./country.ipl";
import anonymizer from "./anonymizer.ipl";

const sources = { country, anonymizer };
const opened = {};

export default {
  async fetch(request) {
    const { searchParams } = new URL(request.url);
    const name = searchParams.get("database");
    try {
      const source = sources[name] ?? new Uint8Array(64);
      opened[name] ??= await open(new Response(source), wasm);
      return Response.json(opened[name].lookup(searchParams.get("address")));
    } catch (error) {
      const status = error instanceof TypeError ? 400 : 500;
      return new Response(error.name, { status });
    }
  },
};
`;

const module = (type, name, contents) => ({ type, path: name, contents });
const miniflare = new Miniflare({
  compatibilityDate: "2025-01-01",
  modules: [
    module("ESModule", "worker.mjs", worker),
    module("ESModule", "iplore.js", readFileSync(here("../dist/index.js"))),
    module("CompiledWasm", "iplore.wasm", readFileSync(here("../dist/iplore.wasm"))),
    ...databases.map((name) =>
      module("Data", `${name}.ipl`, readFileSync(`${dataDirectory}/iplore-${name}.ipl`)),
    ),
  ],
});

async function ask(database, address) {
  const query = new URLSearchParams({ database, address });
  return miniflare.dispatchFetch(`http://localhost/?${query}`);
}

try {
  for (const database of databases) {
    for (const address of addresses) {
      const file = `${dataDirectory}/iplore-${database}.ipl`;
      const output = execFileSync(cli, [file, address], { encoding: "utf8" });
      const expected = JSON.parse(output);
      const response = await ask(database, address);
      assert.deepEqual(await response.json(), expected, `${database} ${address}`);
    }
  }
  assert.equal((await ask("country", "nope")).status, 400);
  assert.equal((await ask("country", " 1.1.1.1")).status, 400);
  const corrupt = await ask("corrupt", "1.1.1.1");
  assert.equal(corrupt.status, 500);
  assert.equal(await corrupt.text(), "DatabaseError");
  console.log(`workerd: ${databases.length * addresses.length + 3} checks passed`);
} finally {
  await miniflare.dispose();
}
