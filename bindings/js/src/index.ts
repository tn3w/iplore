type Group<Fields> = { [Name in keyof Fields]: Fields[Name] | null };

export type City = Group<{
  name: string;
  geonames_id: number;
  population: number;
  district: string;
  postal: string;
  metro: string;
  timezone: string;
}>;

export type Region = Group<{ name: string; iso: string; geonames_id: number }>;

export type Country = Group<{
  code: string;
  name: string;
  continent: string;
  currency: string;
  calling_code: string;
  languages: string;
  eu: boolean;
}>;

export type Place = Group<{
  lat: number;
  lon: number;
  accuracy: number;
  confidence: number;
  city: City;
  region: Region;
  country: Country;
}>;

export type Operator = Group<{
  company: string;
  category: string;
  website: string;
  address: string;
  country: string;
  abuse_email: string;
  since: number;
  tier: number;
  cone: number;
}>;

export type Network = Group<{
  asn: number;
  handle: string;
  prefix: number;
  rir: string;
  country: string;
  year: number;
  rpki: string;
  users: number;
  mobile_code: string;
  risk: number;
  operator: Operator;
}>;

export type Abuse = Group<{
  risk: number;
  threat: string;
  reports: number;
  last_seen_days: number;
  service: string;
  evidence: string;
  provider: string;
  user_type: string;
  flags: string[];
}>;

export type Answer = Group<{ place: Place; network: Network; abuse: Abuse }>;

export interface Database {
  lookup(address: string): Answer;
  about(): Record<string, unknown>;
}

export type Source = Response | ArrayBuffer | ArrayBufferView;

export class DatabaseError extends Error {
  override name = "DatabaseError";
}

const okStatus = 0;
const invalidAddressStatus = 1;
const maxDatabaseBytes = 1 << 30;

interface Exports {
  memory: WebAssembly.Memory;
  allocate(length: number): number;
  output(): number;
  output_length(): number;
  load(pointer: number, length: number): number;
  lookup(pointer: number, length: number): number;
  about(): number;
}

let defaultModule: Promise<WebAssembly.Module> | undefined;

async function loadDefaultModule(): Promise<WebAssembly.Module> {
  const url = new URL("iplore.wasm", import.meta.url);
  if (url.protocol !== "file:") {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`wasm download failed: ${response.status}`);
    return WebAssembly.compile(await response.arrayBuffer());
  }
  const files = "node:fs/promises";
  return WebAssembly.compile(await (await import(files)).readFile(url));
}

function getDefaultModule(): Promise<WebAssembly.Module> {
  defaultModule ??= loadDefaultModule().catch((error) => {
    defaultModule = undefined;
    throw error;
  });
  return defaultModule;
}

const isArrayBuffer = (value: unknown): value is ArrayBuffer =>
  Object.prototype.toString.call(value) === "[object ArrayBuffer]";

async function toBytes(source: Source): Promise<Uint8Array> {
  if (ArrayBuffer.isView(source)) {
    return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  }
  if (isArrayBuffer(source)) return new Uint8Array(source);
  const response = source as Response;
  if (typeof response?.arrayBuffer !== "function") {
    throw new TypeError("source must be a Response, ArrayBuffer or typed array");
  }
  if (response.ok === false) throw new Error(`download failed: ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

function write(wasm: Exports, bytes: Uint8Array): number {
  const pointer = wasm.allocate(bytes.length);
  new Uint8Array(wasm.memory.buffer, pointer, bytes.length).set(bytes);
  return pointer;
}

function read(wasm: Exports): string {
  const bytes = new Uint8Array(wasm.memory.buffer, wasm.output(), wasm.output_length());
  return new TextDecoder().decode(bytes);
}

export async function open(
  source: Source,
  module?: WebAssembly.Module,
): Promise<Database> {
  const bytes = await toBytes(source);
  if (bytes.length > maxDatabaseBytes) {
    throw new DatabaseError(`database too large: ${bytes.length} bytes`);
  }
  const compiled = module ?? (await getDefaultModule());
  const instance = await WebAssembly.instantiate(compiled, {});
  const wasm = instance.exports as unknown as Exports;
  let dead = false;

  const call = (action: () => number, address = ""): string => {
    if (dead) throw new DatabaseError("unusable after a WebAssembly trap");
    try {
      const status = action();
      if (status === okStatus) return read(wasm);
      if (status === invalidAddressStatus) {
        throw new TypeError(`invalid address: ${address}`);
      }
      throw new DatabaseError(read(wasm));
    } catch (error) {
      if (!(error instanceof WebAssembly.RuntimeError)) throw error;
      dead = true;
      throw new DatabaseError(`WebAssembly trap: ${error.message}`, { cause: error });
    }
  };

  call(() => wasm.load(write(wasm, bytes), bytes.length));
  return {
    lookup(address) {
      if (typeof address !== "string") throw new TypeError("address must be a string");
      const encoded = new TextEncoder().encode(address);
      const run = () => wasm.lookup(write(wasm, encoded), encoded.length);
      return JSON.parse(call(run, address));
    },
    about: () => JSON.parse(call(() => wasm.about())),
  };
}
