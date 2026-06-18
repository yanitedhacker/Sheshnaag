"""V6 W5 — offensive research workbench backends."""

from __future__ import annotations

import pytest

from app.lab.research.crash_triage import CrashTriage
from app.lab.research.fuzzing import FuzzingHarness


@pytest.mark.unit
def test_fuzzing_produces_crash_and_triage():
    fuzz = FuzzingHarness().launch(target_binary="/lab/bin", engine="afl", corpus=[b"a", b"b", b"c"])
    assert fuzz["crashes"]
    triage = CrashTriage().triage(crash=fuzz["crashes"][0])
    assert triage["verdict"] in {"exploitable", "needs_review", "not_exploitable"}
