"""Synthetic process ownership; no tmux or API calls."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from test_runner import _runner_settings

from opsgate.runner import OpsGateRunner


def test_owner_process_death_releases_canonical_root(tmp_path: Path) -> None:
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(Path("src").resolve()), str(Path("tests").resolve())]))
    code = (
        "import sys; from pathlib import Path; from test_runner import _runner_settings; "
        "from opsgate.runner import OpsGateRunner; "
        "runner=OpsGateRunner(_runner_settings(Path(sys.argv[1]))); "
        "print('ready', flush=True); sys.stdin.read()"
    )
    with subprocess.Popen([sys.executable, "-c", code, str(tmp_path)], env=env,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as child:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "ready"
        root = tmp_path / "execution"
        evidence = root / "runner-state" / "retained.json"
        evidence.write_text("evidence")
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        with pytest.raises(RuntimeError, match="already owned"):
            OpsGateRunner(_runner_settings(alias))
        child.kill()
        child.wait(timeout=5)
    owner = OpsGateRunner(_runner_settings(tmp_path))
    assert owner.state_dir == root.resolve() / "runner-state"
    assert evidence.read_text() == "evidence"
