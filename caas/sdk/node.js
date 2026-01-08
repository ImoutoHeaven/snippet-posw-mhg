export function createCaasClient({ caasOrigin, serviceToken, apiPrefix = "/__pow/v1" }) {
  if (!caasOrigin) throw new Error("caasOrigin required");
  if (!serviceToken) throw new Error("serviceToken required");

  const origin = String(caasOrigin).replace(/\/+$/, "");
  const auth = `Bearer ${serviceToken}`;
  let prefix = String(apiPrefix || "/__pow/v1").trim();
  if (!prefix) throw new Error("apiPrefix invalid");
  if (!prefix.startsWith("/")) prefix = `/${prefix}`;
  prefix = prefix.replace(/\/+$/, "");
  if (prefix === "/") throw new Error("apiPrefix invalid");

  const postJson = async (path, body) => {
    const res = await fetch(`${origin}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: auth,
      },
      body: JSON.stringify(body ?? {}),
    });
    const text = await res.text();
    let json;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    if (!res.ok) {
      const err = new Error(`CaaS ${path} failed (${res.status})`);
      err.status = res.status;
      err.body = text;
      throw err;
    }
    return json;
  };

  return {
    generate(body) {
      return postJson(`${prefix}/server/generate`, body);
    },
    attest(body) {
      return postJson(`${prefix}/server/attest`, body);
    },
  };
}
