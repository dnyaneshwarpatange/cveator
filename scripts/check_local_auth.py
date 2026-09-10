"""Check real frontend auth routing without creating accounts or sending mail.

Run after scripts/run_local.py: python scripts/check_local_auth.py
These checks exercise the HTTP server, unlike mocked route-handler unit tests.
"""

import argparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:3002")
    args = parser.parse_args()
    base = args.url.rstrip("/")
    checks = [
        ("/login", "GET", None, 200),
        ("/register", "GET", None, 200),
        ("/api/session", "GET", None, 401),
        ("/api/session/login", "POST", b"{}", 422),
        ("/api/session/register", "POST", b"{}", 422),
        ("/api/session/register/verify", "POST", b"{}", 422),
    ]
    failures = []
    for path, method, body, expected in checks:
        request = Request(base + path, data=body, method=method, headers={
            "Origin": base, "Content-Type": "application/json",
        })
        try:
            response = urlopen(request, timeout=90)
        except HTTPError as error:
            response = error
        except OSError as error:
            print(f"FAIL {method} {path}: {type(error).__name__}")
            failures.append(path)
            continue
        with response:
            valid = response.status == expected
            if path.startswith("/api/"):
                valid = valid and response.headers.get_content_type() == "application/json"
            print(f"{'PASS' if valid else 'FAIL'} {method} {path}: "
                  f"HTTP {response.status} (expected {expected})")
            if not valid:
                failures.append(path)
    if failures:
        raise SystemExit("Auth HTTP checks failed. Inspect frontend and API logs.")


if __name__ == "__main__":
    main()
