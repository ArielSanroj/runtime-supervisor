function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function str2bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

async function hmacSha256(key: string, msg: string): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    "raw",
    str2bytes(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", k, str2bytes(msg));
  return new Uint8Array(sig);
}

export async function signHS256(claims: Record<string, unknown>, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64urlEncode(str2bytes(JSON.stringify(header)));
  const p = b64urlEncode(str2bytes(JSON.stringify(claims)));
  const sig = await hmacSha256(secret, `${h}.${p}`);
  return `${h}.${p}.${b64urlEncode(sig)}`;
}

export async function buildToken(
  appId: string,
  scopes: string[],
  secret: string,
  ttlSeconds = 300,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signHS256({ sub: appId, scopes, iat: now, exp: now + ttlSeconds }, secret);
}
