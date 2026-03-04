from __future__ import annotations

import argparse

from waitress import serve  # type: ignore[import-untyped]

from .app import create_app
from .config import load_settings
from .runner import run_runner


def main() -> None:
    parser = argparse.ArgumentParser(description="OpsGate control service")
    parser.add_argument("command", nargs="?", default="serve", choices=["serve", "runner"])
    parser.add_argument("--once", action="store_true", help="Run one runner iteration and exit (runner mode only)")
    args = parser.parse_args()

    if args.command == "serve":
        settings = load_settings()
        app = create_app(settings)
        serve(
            app,
            host=settings.bind_host,
            port=settings.bind_port,
            threads=8,
            expose_tracebacks=False,
        )
        return

    if args.command == "runner":
        run_runner(once=args.once)
        return


if __name__ == "__main__":
    main()
