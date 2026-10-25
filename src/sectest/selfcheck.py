"""`sectest selfcheck`: prove a scanner job's container could do a real run, and do nothing.

After every deploy, `make smoke` (scripts/smoke.sh) starts one run of each
scanner job with its args set to `selfcheck`. That run gets everything a real
one does — the image, the managed identity, the env and Key Vault access — and
checks what a scan needs before it starts: the configuration is valid, the ZAP
scripts are on PATH, Resource Graph answers the discovery query, the report
container is reachable, and the digest's secrets resolve. It requests nothing
from any app, attacks nothing, uploads nothing and sends nothing.

Exits 1 if any check fails, naming each failure but never a secret's value. A
failure fails the smoke test, which rolls the deploy back.
"""

from __future__ import annotations

import logging
import os
import shutil
from collections.abc import Callable

from . import mailer, scan

logger = logging.getLogger(__name__)

# What build_command can invoke.
ZAP_SCRIPTS = ("zap-baseline.py", "zap-full-scan.py", "zap-api-scan.py")


def checks() -> list[tuple[str, Callable[[], object]]]:
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import ContainerClient

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)

    def config() -> None:
        for name in ("TARGET_SUBSCRIPTION_IDS", "REPORT_CONTAINER_URL"):
            if not os.environ.get(name, "").strip():
                raise ValueError(f"{name} is not set")
        if os.environ.get("SCAN_PROFILE", "passive") not in scan.PROFILES:
            raise ValueError(f"SCAN_PROFILE must be one of {list(scan.PROFILES)}")
        if os.environ.get("SCAN_FAIL_ON", "High") not in scan.RISK_LEVELS:
            raise ValueError(f"SCAN_FAIL_ON must be one of {list(scan.RISK_LEVELS)}")

    def zap() -> None:
        missing = [s for s in ZAP_SCRIPTS if shutil.which(s) is None]
        if missing:
            raise FileNotFoundError(f"not on PATH: {', '.join(missing)}")

    def discovery() -> None:
        subscriptions = [s.strip() for s in os.environ["TARGET_SUBSCRIPTION_IDS"].split(",") if s.strip()]
        scan.discover_targets(credential, subscriptions)

    def reports() -> None:
        ContainerClient.from_container_url(
            os.environ["REPORT_CONTAINER_URL"], credential=credential
        ).get_container_properties()

    def digest_secrets() -> None:
        # The same rule as mailer.send: no recipient skips the digest, but a
        # recipient without an API key is a failed send.
        if mailer.get_secret("DIGEST-EMAIL-TO", credential) and not mailer.get_secret(
            "RESEND-API-KEY", credential
        ):
            raise ValueError("DIGEST-EMAIL-TO is set but RESEND-API-KEY is not")

    return [
        ("config", config),
        ("zap scripts", zap),
        ("discovery (Resource Graph)", discovery),
        ("report container", reports),
        ("digest secrets", digest_secrets),
    ]


def run() -> int:
    failed = 0
    for label, check in checks():
        try:
            check()
        except Exception as exc:
            failed += 1
            logger.error("selfcheck: FAIL %s: %s: %s", label, type(exc).__name__, str(exc)[:300])
        else:
            logger.info("selfcheck: ok %s", label)
    if failed:
        logger.error("selfcheck: %d check(s) failed", failed)
        return 1
    logger.info("selfcheck: all checks passed")
    return 0
