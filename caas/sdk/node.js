export function createCaasClient({ caasOrigin, serviceToken }) {
  if (!caasOrigin) throw new Error("caasOrigin required");
  if (!serviceToken) throw new Error("serviceToken required");

  const origin = String(caasOrigin).replace(/\/+$/, "");
  const auth = `Bearer ${serviceToken}`;

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
      return postJson("/__pow/v1/server/generate", body);
    },
    attest(body) {
      return postJson("/__pow/v1/server/attest", body);
    },
  };
}

