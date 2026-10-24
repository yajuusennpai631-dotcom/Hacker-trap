#!/usr/bin/env python3
"""Bounded, clearly identified smoke-crawler for the HomeNest Cam honeypot.

Run manually: python3 tools/test_crawler.py
This script can only contact the project's fixed Railway hostname. It makes
at most 18 GET requests, spaces requests by 2 seconds, and never submits forms.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.request

BASE_URL = "https://honeypot-web-production.up.railway.app"
ALLOWED_HOST = "honeypot-web-production.up.railway.app"
USER_AGENT = "HomeNest-TestCrawler/1.0 (owner-run bounded smoke test)"
PATHS = (
    "/",
    "/login",
    "/admin",
    "/config",
    "/api/status",
    "/fake-shell",
)
ROUNDS = 3
DELAY_SECONDS = 2.0
TIMEOUT_SECONDS = 5


def main() -> None:
    # Guard against accidental edits that would send requests to another host.
    from urllib.parse import urlsplit

    parsed = urlsplit(BASE_URL)
    if parsed.scheme != "https" or parsed.hostname != ALLOWED_HOST:
        raise SystemExit("Safety check failed: target host is not allowlisted.")

    total = ROUNDS * len(PATHS)
    print(f"Starting bounded test crawl: {total} GET requests maximum.")
    print(f"Target: {ALLOWED_HOST}; interval: {DELAY_SECONDS:g}s; rounds: {ROUNDS}")
    completed = 0

    for round_no in range(1, ROUNDS + 1):
        for path in PATHS:
            url = BASE_URL + path
            request = urllib.request.Request(
                url,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json"},
                method="GET",
            )
            try:
                with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                    status = response.status
                print(f"[{completed + 1:02d}/{total}] GET {path} -> {status}")
            except urllib.error.HTTPError as exc:
                # A 4xx/5xx response is still a completed request; report and continue.
                print(f"[{completed + 1:02d}/{total}] GET {path} -> HTTP {exc.code}")
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                print(f"[{completed + 1:02d}/{total}] GET {path} -> request failed ({exc})")
            completed += 1
            if completed < total:
                time.sleep(DELAY_SECONDS)

    print(f"Finished. Attempted {completed} requests; no form submissions were sent.")


if __name__ == "__main__":
    main()
