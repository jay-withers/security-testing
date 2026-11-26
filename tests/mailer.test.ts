// The mailer: no Resend, no Key Vault. A port of tests/test_digest.py's
// mailer cases.

import { afterEach, describe, expect, it } from "vitest";

import * as mailer from "../src/mailer.ts";
import type { SecretStore } from "../src/mailer.ts";

const secrets =
  (values: Record<string, string> = {}): mailer.Secret =>
  async (name) =>
    values[name] ?? null;

const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("send", () => {
  it("skips without posting when there is no recipient", async () => {
    const result = await mailer.send("s", "h", "t", "from", secrets(), async () => {
      throw new Error("posted");
    });
    expect(result.status).toBe("skipped");
  });

  it("sends to every recipient, with a User-Agent", async () => {
    const calls: Parameters<mailer.Post>[] = [];
    const result = await mailer.send(
      "s",
      "h",
      "t",
      "Scans <s@example.com>",
      secrets({
        "DIGEST-EMAIL-TO": "a@example.com, b@example.com",
        "RESEND-API-KEY": "re_x",
      }),
      async (...args) => {
        calls.push(args);
        return { id: "abc" };
      },
    );

    expect(result).toEqual({ status: "sent", provider_id: "abc", error: null });
    const [url, body, headers] = calls[0] as Parameters<mailer.Post>;
    expect(url).toBe(mailer.RESEND_ENDPOINT);
    expect(body.to).toEqual(["a@example.com", "b@example.com"]);
    expect(headers.Authorization).toBe("Bearer re_x");
    expect(headers["User-Agent"]).toBe(mailer.USER_AGENT);
  });

  it("records no provider id when Resend returns none", async () => {
    const values = {
      "DIGEST-EMAIL-TO": "a@example.com",
      "RESEND-API-KEY": "re_x",
    };
    for (const body of [null, "text", { id: 7 }]) {
      const result = await mailer.send("s", "h", "t", "f", secrets(values), async () => body);
      expect(result).toEqual({
        status: "sent",
        provider_id: null,
        error: null,
      });
    }
  });

  it.each([
    [{ "DIGEST-EMAIL-TO": "a@example.com" }],
    [{ "DIGEST-EMAIL-TO": "a@example.com", "RESEND-API-KEY": "re_x" }],
  ])("returns a failed send rather than throwing (%j)", async (values) => {
    const result = await mailer.send("s", "h", "t", "from", secrets(values), async () => {
      throw new Error("network down");
    });
    expect(result.status).toBe("failed");
  });

  it("names a thrown non-Error as itself", async () => {
    const result = await mailer.send("s", "h", "t", "f", () => Promise.reject("vault down"));
    expect(result).toEqual({
      status: "failed",
      provider_id: null,
      error: "vault down",
    });
  });

  it("keeps Resend's explanation of a rejection", async () => {
    // The status line alone says nothing; the reason is in the body.
    globalThis.fetch = (async (_url: string, init: RequestInit) => {
      expect(new Headers(init.headers).get("User-Agent")).toBe(mailer.USER_AGENT);
      return new Response('{"message":"domain not verified"}', {
        status: 403,
        statusText: "Forbidden",
      });
    }) as typeof fetch;

    const result = await mailer.send(
      "s",
      "h",
      "t",
      "from",
      secrets({ "DIGEST-EMAIL-TO": "a@example.com", "RESEND-API-KEY": "re_x" }),
    );

    expect(result.status).toBe("failed");
    expect(result.error).toContain("HTTP 403");
    expect(result.error).toContain("domain not verified");
  });
});

describe("post", () => {
  it("sends JSON and reads the JSON back", async () => {
    const seen: RequestInit[] = [];
    globalThis.fetch = (async (_url: string, init: RequestInit) => {
      seen.push(init);
      return new Response('{"id":"abc"}', { status: 200 });
    }) as typeof fetch;

    expect(await mailer.post(mailer.RESEND_ENDPOINT, { to: ["a"] }, {})).toEqual({ id: "abc" });
    expect(seen[0]?.method).toBe("POST");
    expect(seen[0]?.body).toBe('{"to":["a"]}');
  });

  it("reads an empty success as an empty object", async () => {
    globalThis.fetch = (async () => new Response("", { status: 200 })) as typeof fetch;
    expect(await mailer.post(mailer.RESEND_ENDPOINT, {}, {})).toEqual({});
  });

  it("falls back to the status text for a rejection with no body", async () => {
    globalThis.fetch = (async () =>
      new Response("", {
        status: 401,
        statusText: "Unauthorized",
      })) as typeof fetch;
    await expect(mailer.post(mailer.RESEND_ENDPOINT, {}, {})).rejects.toThrow("HTTP 401: Unauthorized");
  });
});

/** A fake Key Vault behind `SecretClient`: name -> value, a missing name a 404. */
function vault(stored: Record<string, string>) {
  const uris: string[] = [];
  const make = (uri: string): SecretStore => {
    uris.push(uri);
    return {
      async getSecret(name) {
        if (!(name in stored)) {
          throw Object.assign(new Error(`${name} not found`), {
            statusCode: 404,
          });
        }
        return { value: stored[name] };
      },
    };
  };
  return { make, uris };
}

describe("getSecret", () => {
  it("lets the environment win over the vault", async () => {
    const { make } = vault({});
    expect(
      await mailer.getSecret("DIGEST-EMAIL-TO", make, {
        DIGEST_EMAIL_TO: "me@example.com",
      }),
    ).toBe("me@example.com");
    expect(await mailer.getSecret("RESEND-API-KEY", make, {})).toBeNull();
  });

  it("asks the vault when the environment does not answer", async () => {
    const { make, uris } = vault({ "DIGEST-EMAIL-TO": "me@example.com" });
    const env = { KEY_VAULT_URI: "https://kv.example.vault.azure.net/" };

    expect(await mailer.getSecret("DIGEST-EMAIL-TO", make, env)).toBe("me@example.com");
    expect(uris).toEqual(["https://kv.example.vault.azure.net/"]);
  });

  it.each([[{}], [{ "DIGEST-EMAIL-TO": "" }]])(
    "reads a missing or empty vault secret as null (%j)",
    async (stored) => {
      // Null is what makes `send` skip: the digest is switched on by setting the secret.
      const { make } = vault(stored);
      const env = { KEY_VAULT_URI: "https://kv.example.vault.azure.net/" };
      expect(await mailer.getSecret("DIGEST-EMAIL-TO", make, env)).toBeNull();
    },
  );

  it("lets any other vault error through", async () => {
    const failing = () => ({
      getSecret: () => Promise.reject(Object.assign(new Error("forbidden"), { statusCode: 403 })),
    });
    await expect(
      mailer.getSecret("DIGEST-EMAIL-TO", failing, {
        KEY_VAULT_URI: "https://kv.example/",
      }),
    ).rejects.toThrow("forbidden");
  });
});
