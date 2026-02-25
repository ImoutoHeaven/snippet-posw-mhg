const encoder = new TextEncoder();

const concat = (...chunks) => {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

const sha256 = async (...chunks) => {
  const bytes = concat(...chunks);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
};

const b64uToBytes = (value) => {
  const raw = String(value || "");
  if (!raw) return null;
  let b64 = raw.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
};

export async function deriveGraphSeed16FromTicketNonce(ticketB64, nonceString) {
  const digest = await sha256(
    encoder.encode("mhg|graph|v4|"),
    encoder.encode(ticketB64),
    encoder.encode("|"),
    encoder.encode(nonceString)
  );
  return digest.slice(0, 16);
}

export async function deriveNonce16FromCommitNonce(nonceString) {
  const raw = b64uToBytes(nonceString);
  if (!raw) {
    return (await sha256(encoder.encode(nonceString))).slice(0, 16);
  }
  if (raw.length >= 16) return raw.slice(0, 16);
  return (await sha256(raw)).slice(0, 16);
}

export function deriveLeafCountFromSteps(steps) {
  return steps + 1;
}
