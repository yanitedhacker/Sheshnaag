"""Tests for executable P0 checks in the beta acceptance gate."""

from __future__ import annotations

import scripts.sheshnaag_beta_acceptance as acceptance


def test_duplicate_scan_ignores_dependency_and_build_directories(
    monkeypatch,
    tmp_path,
):
    duplicate = tmp_path / "src" / "report 2.json"
    ignored = [
        tmp_path / ".venv-v2" / "lib" / "package 2.py",
        tmp_path / "frontend" / "node_modules" / "package 2.js",
        tmp_path / "frontend" / "dist" / "chunk 2.js",
        tmp_path / ".pytest_cache" / "result 2.json",
    ]
    duplicate.parent.mkdir(parents=True)
    duplicate.write_text("{}", encoding="utf-8")
    for path in ignored:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ignored", encoding="utf-8")
    monkeypatch.setattr(acceptance, "ROOT", tmp_path)

    assert acceptance._find_duplicate_artifacts() == ["src/report 2.json"]


def test_p0_integrity_gate_executes_named_behavior_tests(monkeypatch):
    captured: dict[str, object] = {}

    def fake_run(argv, *, timeout=60, env=None):
        captured["argv"] = argv
        captured["timeout"] = timeout
        captured["env"] = env
        return 0, "8 passed in 1.00s"

    monkeypatch.setattr(acceptance, "_run", fake_run)

    result = acceptance._run_p0_integrity_tests()

    assert result["status"] == "ok"
    assert result["returncode"] == 0
    assert result["output"] == "8 passed in 1.00s"
    assert captured["argv"][:4] == [
        acceptance.sys.executable,
        "-m",
        "pytest",
        "-q",
    ]
    assert captured["env"] == {"RUN_INTEGRATION_TESTS": "1"}
    assert set(acceptance.P0_INTEGRITY_TESTS).issubset(set(captured["argv"]))


def test_p0_integrity_gate_blocks_on_test_failure(monkeypatch):
    monkeypatch.setattr(
        acceptance,
        "_run",
        lambda argv, *, timeout=60, env=None: (1, "1 failed, 7 passed"),
    )

    result = acceptance._run_p0_integrity_tests()

    assert result == {
        "status": "failed",
        "returncode": 1,
        "tests": list(acceptance.P0_INTEGRITY_TESTS),
        "output": "1 failed, 7 passed",
    }
