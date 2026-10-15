"""The digest email, via Resend.

Adapted from jay-withers/finances src/finances/mailer.py: the same provider,
the same Key Vault secrets and the same contract, without that repo's
settings module or httpx. Fix contract bugs in both.

**Sending never raises.** It returns what happened, and the caller logs it.

**An absent `DIGEST-EMAIL-TO` means skip**, not fail, so the digest has to be
switched on deliberately. The recipients and the API key come from Key Vault
at run time, not from Terraform: a personal address in a public repository is
permanent, and a runtime lookup means changing it needs no redeploy. Locally,
`DIGEST_EMAIL_TO` and `RESEND_API_KEY` in the environment win.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

RESEND_ENDPOINT = "https://api.resend.com/emails"
TIMEOUT_SECONDS = 20
# Resend sits behind Cloudflare, which rejects urllib's default User-Agent
# with a 403 ("error code: 1010") before the request reaches the API.
USER_AGENT = "sectest-digest (+https://github.com/jay-withers/security-testing)"


@dataclass(frozen=True)
class MailResult:
    status: str  # sent | skipped | failed
    provider_id: str | None = None
    error: str | None = None


def get_secret(name: str, credential) -> str | None:
    """A hyphenated Key Vault secret, or None if it does not exist.

    The environment (`DIGEST-EMAIL-TO` as `DIGEST_EMAIL_TO`) wins, which is
    what lets this run locally with no vault.
    """
    from_env = os.environ.get(name.replace("-", "_"))
    if from_env:
        return from_env
    vault = os.environ.get("KEY_VAULT_URI")
    if not vault:
        return None

    from azure.core.exceptions import ResourceNotFoundError
    from azure.keyvault.secrets import SecretClient

    try:
        return SecretClient(vault_url=vault, credential=credential).get_secret(name).value or None
    except ResourceNotFoundError:
        return None


def _post(url: str, body: dict, headers: dict) -> dict:
    # S310: the URL is the fixed Resend endpoint above, never caller-supplied.
    request = urllib.request.Request(  # noqa: S310
        url, data=json.dumps(body).encode(), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        # Resend explains a rejection (an unverified sender, a bad key) in the
        # body; HTTPError's own message is only the status line. The body
        # never echoes the key, so it is safe to log.
        try:
            detail = exc.read().decode(errors="replace")[:500]
        except Exception:
            detail = ""
        raise RuntimeError(f"HTTP {exc.code}: {detail or exc.reason}") from None


def send(
    subject: str,
    html: str,
    text: str,
    sender: str,
    credential,
    secret: Callable[[str, object], str | None] = get_secret,
    post: Callable[[str, dict, dict], dict] = _post,
) -> MailResult:
    """Send one email, returning what happened rather than raising."""
    try:
        recipient = secret("DIGEST-EMAIL-TO", credential)
        if not recipient:
            return MailResult(status="skipped")
        recipients = [a.strip() for a in recipient.split(",") if a.strip()]
        api_key = secret("RESEND-API-KEY", credential)
        if not api_key:
            return MailResult(status="failed", error="DIGEST-EMAIL-TO is set but RESEND-API-KEY is not")
        body = post(
            RESEND_ENDPOINT,
            # Resend takes a list even for one recipient.
            {"from": sender, "to": recipients, "subject": subject, "html": html, "text": text},
            {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
    except Exception as exc:
        return MailResult(status="failed", error=f"{type(exc).__name__}: {exc}")
    return MailResult(status="sent", provider_id=body.get("id") if isinstance(body, dict) else None)
