"""Run a low-memory preview with host Python/Node and container PostgreSQL/Redis."""

import argparse
import os
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit, urlunsplit

from deploy import ROOT, compose_command, create_local_environment, read_environment, run


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--built", action="store_true", help="Serve an existing npm run build output")
    parser.add_argument("--full", action="store_true", help="Also run Celery worker and scheduler")
    parser.add_argument("--no-demo", action="store_true", help="Do not create synthetic demonstration data")
    parser.add_argument(
        "--enable-email", action="store_true",
        help="Enable scheduled delivery; omit while bootstrapping historical data",
    )
    args = parser.parse_args()
    frontend = ROOT / "frontend"
    if args.built:
        standalone = frontend / ".next" / "standalone"
        if not (standalone / "server.js").is_file():
            raise SystemExit("Run npm --prefix frontend run build before using --built")
        shutil.copytree(frontend / ".next" / "static", standalone / ".next" / "static",
                        dirs_exist_ok=True)
        if (frontend / "public").is_dir():
            shutil.copytree(frontend / "public", standalone / "public", dirs_exist_ok=True)
    env_file = ROOT / ".env"
    if not env_file.exists():
        create_local_environment(env_file)
    values = read_environment(env_file)
    if values.get("APP_ENV", "development") != "development":
        raise SystemExit("The local preview requires APP_ENV=development")
    compose_env = {**os.environ, **values, "ENV_FILE": str(env_file)}
    command = compose_command(env_file, False)
    run(command + ["up", "-d", "--wait", "postgres", "redis"], compose_env, timeout=120)
    db = urlsplit(values["DATABASE_URL"])
    credentials = db.netloc.rsplit("@", 1)[0]
    env = {**compose_env, "DATABASE_URL": urlunsplit(db._replace(netloc=f"{credentials}@127.0.0.1:5432")),
           "REDIS_URL": "redis://127.0.0.1:6379/0", "PUBLIC_APP_URL": "http://localhost:3002",
           "API_INTERNAL_BASE_URL": "http://127.0.0.1:8002", "SESSION_COOKIE_SECURE": "false",
           "NEXT_TELEMETRY_DISABLED": "1"}
    if not args.enable_email:
        env["EMAIL_DELIVERY_ENABLED"] = "false"
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                   cwd=ROOT / "backend", env=env, check=True)
    if not args.no_demo:
        subprocess.run([sys.executable, "-m", "app.scripts.seed_demo"],
                       cwd=ROOT / "backend", env=env, check=True)
    node = "node.exe" if os.name == "nt" else "node"
    processes = []
    bootstrap_process = None
    bootstrap_retry_at = None
    try:
        processes.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app",
                                           "--host", "127.0.0.1", "--port", "8002"],
                                          cwd=ROOT / "backend", env=env))
        web_command = ([node, ".next/standalone/server.js"] if args.built else
                       [node, "node_modules/next/dist/bin/next", "dev", "--hostname", "127.0.0.1", "--port", "3002"])
        processes.append(subprocess.Popen(web_command, cwd=frontend,
                                          env={**env, "HOSTNAME": "127.0.0.1", "PORT": "3002"}))
        if args.full:
            bootstrap_process = subprocess.Popen(
                [sys.executable, "-m", "app.scripts.bootstrap_data"],
                cwd=ROOT / "backend", env=env,
            )
            processes.append(subprocess.Popen([
                sys.executable, "-m", "celery", "-A", "app.worker.celery_app", "worker",
                "--loglevel=INFO", "--pool=solo",
            ], cwd=ROOT / "backend", env=env))
            processes.append(subprocess.Popen([
                sys.executable, "-m", "celery", "-A", "app.worker.celery_app", "beat",
                "--loglevel=INFO",
            ], cwd=ROOT / "backend", env=env))
        print("Local preview starting at http://localhost:3002/login. Ctrl+C stops the preview.", flush=True)
        while all(process.poll() is None for process in processes):
            if bootstrap_process is not None and bootstrap_process.poll() not in (None, 0):
                if bootstrap_retry_at is None:
                    print("Public-data bootstrap failed; retrying from checkpoints in five minutes.",
                          flush=True)
                    bootstrap_retry_at = time.monotonic() + 300
                elif time.monotonic() >= bootstrap_retry_at:
                    bootstrap_process = subprocess.Popen(
                        [sys.executable, "-m", "app.scripts.bootstrap_data"],
                        cwd=ROOT / "backend", env=env,
                    )
                    bootstrap_retry_at = None
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        if bootstrap_process is not None and bootstrap_process.poll() is None:
            bootstrap_process.terminate()
            bootstrap_process.wait(timeout=10)
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    main()
