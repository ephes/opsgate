"""Fake ``codex``/``claude`` for the runner parity harness (rust/PLAN.md 7.4).

The harness installs shims named ``codex`` and ``claude`` first on the
runner's ``PATH``; each runs this script with the name it was called by. The
step prompt arrives on stdin (the runner's command redirects ``prompt.md``),
and its ``fake:`` line says what to do::

    fake: exit=3 lines=5 sleep=2 wait=release-1 marker=started-1

``lines`` lines of deterministic output go to stdout (the step script tees
them into ``session.log``), ``marker`` creates ``<control>/<marker>`` once the
output is written, ``wait`` blocks until ``<control>/<wait>`` exists, ``sleep``
waits that many seconds, and the process exits with ``exit``. Every call
appends one JSON line (agent, arguments, prompt, working directory and the
environment variables the scenarios check) to ``$OPSGATE_PARITY_AGENT_LOG``.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ENV_KEYS = (
    "BASH_ENV",
    "OPSGATE_PARITY_ENV_MARKER",
    "OPSGATE_PARITY_OVERRIDE",
    "OPSGATE_PARITY_PROCESS_MARKER",
    "OPSGATE_RUNNER_TOKEN",
    "OPSGATE_TMUX_SOCKET_LABEL",
)
WAIT_LIMIT_SECONDS = 300.0


def directives(prompt: str) -> dict[str, str]:
    for line in prompt.splitlines():
        if line.startswith("fake:"):
            return dict(part.split("=", 1) for part in line[len("fake:") :].split() if "=" in part)
    return {}


def main() -> int:
    agent = sys.argv[1]
    args = sys.argv[2:]
    prompt = sys.stdin.read()
    spec = directives(prompt)
    control = Path(os.environ.get("OPSGATE_PARITY_CONTROL_DIR", "."))
    log = os.environ.get("OPSGATE_PARITY_AGENT_LOG")
    if log:
        record = {
            "agent": agent,
            "args": args,
            "prompt": prompt,
            "cwd": os.getcwd(),
            "env": {key: os.environ.get(key) for key in ENV_KEYS},
        }
        with open(log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    label = spec.get("label", agent)
    for number in range(1, int(spec.get("lines", "2")) + 1):
        print(f"{label} output line {number}", flush=True)
    if "marker" in spec:
        (control / spec["marker"]).touch()
    if "wait" in spec:
        deadline = time.monotonic() + WAIT_LIMIT_SECONDS
        while not (control / spec["wait"]).exists() and time.monotonic() < deadline:
            time.sleep(0.05)
    if "sleep" in spec:
        time.sleep(float(spec["sleep"]))
    print(f"{label} done", flush=True)
    return int(spec.get("exit", "0"))


if __name__ == "__main__":
    sys.exit(main())
