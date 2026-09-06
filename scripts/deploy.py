"""One-command, health-gated deployment using only Python and Docker Compose."""

import argparse
import os
from pathlib import Path
import secrets
import subprocess
import sys
from urllib.parse import urlparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]


def read_environment(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise ValueError("Environment file contains a line without '='")
        value = value.strip()
        if len(value) > 1 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def create_local_environment(path: Path) -> None:
    password = secrets.token_hex(24)
    template = (ROOT / ".env.example").read_text(encoding="utf-8")
    template = template.replace("change-me", password)
    template = template.replace("replace-with-a-random-64-character-secret-before-production",
                                secrets.token_hex(32))
    template = template.replace("PAYMENT_PROVIDER=razorpay", "PAYMENT_PROVIDER=")
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(template)
    if os.name != "nt":
        path.chmod(0o600)


def compose_command(env_file: Path, production: bool) -> list[str]:
    command = ["docker", "compose", "--project-directory", str(ROOT),
               "--env-file", str(env_file), "-f", str(ROOT / "docker-compose.yml")]
    if production:
        command += ["--profile", "edge", "--profile", "mail", "--profile", "monitoring"]
    return command


def run(command: list[str], env: dict[str, str], *, timeout: int = 1800) -> None:
    subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=timeout)


def validate_target(values: dict[str, str], production: bool) -> None:
    mode = values.get("APP_ENV", "development").lower()
    if production != (mode == "production"):
        raise ValueError("APP_ENV and --production must agree; choose the correct environment file")
    if not production:
        return
    public = urlparse(values.get("PUBLIC_APP_URL", ""))
    if public.scheme != "https" or not public.hostname or "example." in public.hostname:
        raise ValueError("Configure PUBLIC_APP_URL with your real HTTPS domain")
    if values.get("APP_ADDRESS") != public.hostname:
        raise ValueError("APP_ADDRESS must match the hostname in PUBLIC_APP_URL")
    if values.get("SMTP_HOST") == "smtp":
        selector = values.get("DKIM_SELECTOR", "alerts")
        if not selector.replace("-", "").replace("_", "").isalnum():
            raise ValueError("DKIM_SELECTOR must contain only letters, numbers, '-' or '_'")
        key_file = ROOT / "infra" / "postfix" / "secrets" / f"{selector}.private"
        if not key_file.is_file():
            raise ValueError("Generate the DKIM private key using the email setup instructions first")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production", action="store_true")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--no-build", action="store_true", help="Use images already built and tested")
    parser.add_argument("--demo", action="store_true", help="Seed local demo data (never production)")
    args = parser.parse_args()
    env_file = (args.env_file or ROOT / (".env.production" if args.production else ".env")).resolve()
    if args.demo and args.production:
        parser.error("--demo cannot be combined with --production")
    if not env_file.exists():
        if args.production:
            raise ValueError("Create and configure .env.production from .env.production.example first")
        create_local_environment(env_file)
        print("Created a local environment with generated credentials.", flush=True)
    values = read_environment(env_file)
    validate_target(values, args.production)
    # Pass values explicitly so stale shell variables cannot select a different database.
    env = {**os.environ, **values, "ENV_FILE": str(env_file), "COMPOSE_PARALLEL_LIMIT": "1"}
    command = compose_command(env_file, args.production)
    run(["docker", "info", "--format", "{{.ServerVersion}}"], env, timeout=30)
    run(command + ["config", "--quiet"], env, timeout=30)
    if not args.no_build:
        print("Building application images…", flush=True)
        run(command + ["build"], env)
    if args.production:
        print("Checking production configuration…", flush=True)
        run(command + ["run", "--rm", "--no-deps", "api", "python", "-m",
                       "app.scripts.production_preflight"], env, timeout=60)
        current = subprocess.run(command + ["ps", "--status", "running", "-q", "postgres"],
                                 cwd=ROOT, env=env, capture_output=True, text=True, check=True)
        if current.stdout.strip():
            print("Saving a database backup before applying migrations…", flush=True)
            run(command + ["--profile", "maintenance", "run", "--rm", "backup"], env)
    print("Starting services and waiting for health checks…", flush=True)
    run(command + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "180"], env, timeout=240)
    if args.demo:
        run(command + ["exec", "-T", "api", "python", "-m", "app.scripts.seed_demo"], env, timeout=60)
    url = values.get("PUBLIC_APP_URL", "http://localhost:3000").rstrip("/")
    with urlopen(url + "/login", timeout=20) as response:
        if response.status != 200:
            raise RuntimeError("Public login page failed its final HTTP check")
    print(f"\nApplication is ready: {url}/login", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Deployment stopped: {error}", file=sys.stderr)
        print("Inspect 'docker compose ps' and 'docker compose logs --tail 80'.", file=sys.stderr)
        raise SystemExit(1) from None
