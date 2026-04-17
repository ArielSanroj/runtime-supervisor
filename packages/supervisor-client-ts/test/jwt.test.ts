import { describe, expect, it } from "vitest";
import { signHS256 } from "../src/jwt.js";

function b64urlDecode(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const normalized = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(normalized);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

describe("signHS256", () => {
  it("produces three parts joined by dots", async () => {
    const t = await signHS256({ sub: "app1" }, "secret");
    expect(t.split(".")).toHaveLength(3);
  });

  it("encodes claims in the payload segment", async () => {
    const t = await signHS256({ sub: "app1", scopes: ["refund"] }, "secret");
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(t.split(".")[1])));
    expect(payload.sub).toBe("app1");
    expect(payload.scopes).toEqual(["refund"]);
  });

  it("different secrets produce different signatures", async () => {
    const a = await signHS256({ sub: "app1" }, "alice");
    const b = await signHS256({ sub: "app1" }, "bob");
    const sigA = a.split(".")[2];
    const sigB = b.split(".")[2];
    expect(sigA).not.toBe(sigB);
  });

  it("same secret + claims produce same signature (deterministic)", async () => {
    const a = await signHS256({ sub: "app1", scopes: ["x"] }, "s");
    const b = await signHS256({ sub: "app1", scopes: ["x"] }, "s");
    expect(a).toBe(b);
  });
});
