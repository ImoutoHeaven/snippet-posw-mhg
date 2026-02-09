const subtle = globalThis.crypto?.subtle;
const encoder = new TextEncoder();

if (!subtle) {
  throw new Error("WebCrypto subtle API is required");
}

const concatBytes = (...chunks) => {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

const u32be = (value) => {
  const out = new Uint8Array(4);
  const v = value >>> 0;
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  return out;
};

const assertPageBytes = (pageBytes) => {
  if (!Number.isInteger(pageBytes) || pageBytes <= 0 || pageBytes % 16 !== 0) {
    throw new RangeError("pageBytes must be a positive multiple of 16");
  }
};

const assertPage = (name, value, pageBytes) => {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be Uint8Array`);
  }
  if (value.length !== pageBytes) {
    throw new RangeError(`${name} must match pageBytes`);
  }
};

const assert16Bytes = (name, value) => {
  if (!(value instanceof Uint8Array) || value.length !== 16) {
    throw new TypeError(`${name} must be Uint8Array(16)`);
  }
};

const digest = async (...chunks) => {
  const data = concatBytes(...chunks);
  return new Uint8Array(await subtle.digest("SHA-256", data));
};

const xor3 = (a, b, c) => {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = a[i] ^ b[i] ^ c[i];
  }
  return out;
};

const aesCbcNoPadding = async ({ key, iv, input, pageBytes }) => {
  const encrypted = new Uint8Array(
    await subtle.encrypt({ name: "AES-CBC", iv }, key, input),
  );

  // WebCrypto AES-CBC applies PKCS#7 padding; trim the extra block.
  return encrypted.slice(0, pageBytes);
};

const expandSeed = async ({ graphSeed, nonce, pageBytes }) => {
  const out = new Uint8Array(pageBytes);
  let counter = 0;
  let offset = 0;
  while (offset < pageBytes) {
    const block = await digest(
      encoder.encode("mhg:genesis:block"),
      graphSeed,
      nonce,
      u32be(counter),
    );
    const take = Math.min(block.length, pageBytes - offset);
    out.set(block.subarray(0, take), offset);
    offset += take;
    counter += 1;
  }
  return out;
};

export const deriveKey = async ({ graphSeed, nonce, i }) => {
  assert16Bytes("graphSeed", graphSeed);
  assert16Bytes("nonce", nonce);
  if (!Number.isInteger(i) || i < 0 || i > 0xffffffff) {
    throw new RangeError("i must be a non-negative uint32 integer");
  }

  const indexBytes = u32be(i);
  const keyMaterial = await digest(encoder.encode("mhg:key"), graphSeed, nonce, indexBytes);
  const ivMaterial = await digest(encoder.encode("mhg:iv"), graphSeed, nonce, indexBytes);

  const rawKey = keyMaterial.slice(0, 16);
  const key = await subtle.importKey("raw", rawKey, { name: "AES-CBC" }, false, ["encrypt"]);
  const iv = ivMaterial.slice(0, 16);

  return { key, iv };
};

export const makeGenesisPage = async ({ graphSeed, nonce, pageBytes }) => {
  assertPageBytes(pageBytes);
  const seedPage = await expandSeed({ graphSeed, nonce, pageBytes });
  const zeros = new Uint8Array(pageBytes);
  return mixPage({ i: 0, p0: seedPage, p1: zeros, p2: zeros, graphSeed, nonce, pageBytes });
};

export const mixPage = async ({ i, p0, p1, p2, graphSeed, nonce, pageBytes }) => {
  assertPageBytes(pageBytes);
  assertPage("p0", p0, pageBytes);
  assertPage("p1", p1, pageBytes);
  assertPage("p2", p2, pageBytes);

  const inPage = xor3(p0, p1, p2);
  const { key, iv } = await deriveKey({ graphSeed, nonce, i });
  return aesCbcNoPadding({ key, iv, input: inPage, pageBytes });
};
