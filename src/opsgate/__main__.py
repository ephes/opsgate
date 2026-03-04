from __future__ import annotations

import argparse

from waitress import serve  # type: ignore[import-untyped]

from .app import create_app
from .config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="OpsGate control service")
    parser.add_argument("command", nargs="?", default="serve", choices=["serve"]) 
    args = parser.parse_args()

    settings = load_settings()
    app = create_app(settings)

    if args.command == "serve":
        serve(
            app,
            host=settings.bind_host,
            port=settings.bind_port,
            threads=8,
            expose_tracebacks=False,
        )


if __name__ == "__main__":
    main()
