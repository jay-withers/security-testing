/**
 * The digest email, via Resend.
 *
 * Adapted from jay-withers/finances src/finances/mailer.py: the same provider,
 * the same Key Vault secrets and the same contract. Fix contract bugs in both.
 *
 * **Sending never throws.** It resolves what happened, and the caller logs it.
 *
 * **An absent `DIGEST-EMAIL-TO` means skip**, not fail, so the digest has to
 * be switched on deliberately. The recipients and the API key come from Key
 * Vault at run time, not from Terraform: a personal address in a public
 * repository is permanent, and a runtime lookup means changing it needs no
 * redeploy. Locally, `DIGEST_EMAIL_TO` and `RESEND_API_KEY` in the
 * environment win.
 */

export const RESEND_ENDPOINT = "https://api.resend.com/emails";
export const TIMEOUT_SECONDS = 20;
// Resend sits behind Cloudflare, which rejects a client's default User-Agent
// with a 403 ("error code: 1010") before the request reaches the API.
export const USER_AGENT = "sectest-digest (+https://github.com/jay-withers/security-testing)";

export interface MailResult {
  status: "sent" | "skipped" | "failed";
  provider_id: string | null;
  error: string | null;
}

function mailResult(
  status: MailResult["status"],
  fields: Partial<Omit<MailResult, "status">> = {},
): MailResult {
  return { status, provider_id: null, error: null, ...fields };
}

/** The part of Key Vault's SecretClient a lookup uses. */
export interface SecretStore {
  getSecret(name: string): Promise<{ value?: string }>;
}

export type Secret = (name: string) => Promise<string | null>;

/**
 * A hyphenated Key Vault secret, or null if it does not exist or is empty.
 *
 * The environment (`DIGEST-EMAIL-TO` as `DIGEST_EMAIL_TO`) wins, which is what
 * lets this run locally with no vault. `vault` makes the client for
 * KEY_VAULT_URI, and is only called when that is set.
 */
export async function getSecret(
  name: string,
  vault: (uri: string) => SecretStore,
  env: NodeJS.ProcessEnv = process.env,
): Promise<string | null> {
  const fromEnv = env[name.replaceAll("-", "_")];
  if (fromEnv) return fromEnv;
  const uri = env.KEY_VAULT_URI;
  if (!uri) return null;
  try {
    return (await vault(uri).getSecret(name)).value || null;
  } catch (error) {
    if ((error as { statusCode?: number }).statusCode === 404) return null;
    throw error;
  }
}

export type Post = (
  url: string,
  body: Record<string, unknown>,
  headers: Record<string, string>,
) => Promise<unknown>;

export const post: Post = async (url, body, headers) => {
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(TIMEOUT_SECONDS * 1000),
  });
  if (!response.ok) {
    // Resend explains a rejection (an unverified sender, a bad key) in the
    // body; the status line alone says nothing. The body never echoes the
    // key, so it is safe to log.
    const detail = (await response.text().catch(() => "")).slice(0, 500);
    throw new Error(`HTTP ${response.status}: ${detail || response.statusText}`);
  }
  const text = await response.text();
  return text ? JSON.parse(text) : {};
};

function describe(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

/** Send one email, resolving what happened rather than throwing. */
export async function send(
  subject: string,
  html: string,
  text: string,
  sender: string,
  secret: Secret,
  postFn: Post = post,
): Promise<MailResult> {
  let body: unknown;
  try {
    const recipient = await secret("DIGEST-EMAIL-TO");
    if (!recipient) return mailResult("skipped");
    const recipients = recipient
      .split(",")
      .map((a) => a.trim())
      .filter(Boolean);
    const apiKey = await secret("RESEND-API-KEY");
    if (!apiKey) {
      return mailResult("failed", {
        error: "DIGEST-EMAIL-TO is set but RESEND-API-KEY is not",
      });
    }
    body = await postFn(
      RESEND_ENDPOINT,
      // Resend takes a list even for one recipient.
      { from: sender, to: recipients, subject, html, text },
      {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
      },
    );
  } catch (error) {
    return mailResult("failed", { error: describe(error) });
  }
  const id = body !== null && typeof body === "object" ? (body as { id?: unknown }).id : undefined;
  return mailResult("sent", {
    provider_id: typeof id === "string" ? id : null,
  });
}
