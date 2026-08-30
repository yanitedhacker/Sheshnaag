"""Contract tests for the fail-closed real-detonation operator harness."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests" / "e2e" / "test_real_detonation.sh"


def _write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    path.chmod(0o755)


def _fake_commands(tmp_path: Path) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(
        bin_dir / "uname",
        """
        #!/usr/bin/env bash
        printf 'Linux\n'
        """,
    )
    for name in ("virsh", "zeek"):
        _write_executable(
            bin_dir / name,
            """
            #!/usr/bin/env bash
            exit 0
            """,
        )
    _write_executable(
        bin_dir / "git",
        r"""
        #!/usr/bin/env bash
        case " $* " in
          *" status --porcelain "*)
            if [[ "${FAKE_GIT_DIRTY:-0}" == "1" ]]; then
              printf '%s\n' ' M app/main.py'
            fi
            ;;
          *" rev-parse --show-toplevel "*)
            printf '%s\n' "${FAKE_REPO_ROOT}"
            ;;
          *" rev-parse HEAD "*)
            printf '%040d\n' 0
            ;;
          *)
            exit 2
            ;;
        esac
        """,
    )
    _write_executable(
        bin_dir / "curl",
        r"""
        #!/usr/bin/env bash
        url=""
        for arg in "$@"; do
          if [[ -n "${SHESHNAAG_ACCESS_TOKEN:-}" && "$arg" == *"${SHESHNAAG_ACCESS_TOKEN}"* ]]; then
            printf '%s\n' 'access token appeared in curl argv' >&2
            exit 92
          fi
          case "$arg" in
            http://*|https://*) url="$arg" ;;
          esac
        done
        case "$url" in
          */api/ops/health)
            printf '%s\n' '{"api":"ok","lab_deps":{"kvm":"ok","virsh":"ok","zeek":"ok"},"detonation_runtime":{"egress_enforce":"on","pcap":"on"}}'
            ;;
          */api/specimens/upload)
            printf '%s\n' "{\"id\":11,\"latest_revision\":{\"sha256\":\"${FAKE_SPECIMEN_SHA:-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f}\"}}"
            ;;
          */api/analysis-cases)
            printf '%s\n' '{"id":21}'
            ;;
          */api/runs)
            printf '%s\n' '{"id":42,"provider":"libvirt","state":"queued"}'
            ;;
          */api/runs/42\?*)
            printf '%s\n' '{"id":42,"provider":"libvirt","state":"completed","manifest":{"detonation_preflight":{"status":"ok"},"worker_execution":{"status":"completed","live_evidence_count":2}},"timeline":[{"event_type":"run_queued"},{"event_type":"run_started"},{"event_type":"run_completed"}]}'
            ;;
          */api/evidence\?*)
            printf '%s\n' '{"count":1,"items":[{"id":51,"run_id":42,"collector_status":"completed"}]}'
            ;;
          */api/v4/runs/42/events\?*)
            if [[ "${FAKE_SSE_COMPLETE:-1}" == "1" ]]; then
              printf 'event: run_event\ndata: {"type":"run_completed","run_id":42}\n\n'
            else
              printf 'event: run_event\ndata: {"type":"run_started","run_id":42}\n\n'
            fi
            ;;
          *)
            printf '%s\n' '{}'
            ;;
        esac
        """,
    )
    kvm = tmp_path / "kvm"
    kvm.write_bytes(b"")
    kvm.chmod(0o600)
    return bin_dir, kvm


def _run_harness(
    tmp_path: Path,
    *,
    token: str | None = "test-secret-token",
    tenant: str = "private-lab",
    kvm_exists: bool = True,
    sse_complete: bool = True,
    retain_output: bool = False,
    git_dirty: bool = False,
    specimen_sha_matches: bool = True,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    bin_dir, kvm = _fake_commands(tmp_path)
    output_dir = tmp_path / "proof"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{bin_dir}:{env['PATH']}",
            "SHESHNAAG_API": "http://control.test",
            "SHESHNAAG_TENANT": tenant,
            "SHESHNAAG_RECIPE_ID": "7",
            "SHESHNAAG_TIMEOUT": "2",
            "SHESHNAAG_KVM_DEVICE": str(kvm if kvm_exists else tmp_path / "missing-kvm"),
            "FAKE_SSE_COMPLETE": "1" if sse_complete else "0",
            "FAKE_GIT_DIRTY": "1" if git_dirty else "0",
            "FAKE_REPO_ROOT": str(ROOT),
            "FAKE_SPECIMEN_SHA": (
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                if specimen_sha_matches
                else "b" * 64
            ),
        }
    )
    if token is None:
        env.pop("SHESHNAAG_ACCESS_TOKEN", None)
    else:
        env["SHESHNAAG_ACCESS_TOKEN"] = token
    if retain_output:
        env["SHESHNAAG_E2E_OUTPUT_DIR"] = str(output_dir)
    else:
        env.pop("SHESHNAAG_E2E_OUTPUT_DIR", None)

    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result, output_dir


def test_missing_token_fails_before_any_api_mutation(tmp_path):
    result, _ = _run_harness(tmp_path, token=None)

    assert result.returncode == 2
    assert "SHESHNAAG_ACCESS_TOKEN" in result.stdout


def test_demo_tenant_is_rejected_and_token_is_never_printed(tmp_path):
    token = "must-not-appear-in-output"
    result, _ = _run_harness(tmp_path, token=token, tenant="demo-public")

    assert result.returncode == 2
    assert "demo-public" in result.stdout
    assert token not in result.stdout + result.stderr


def test_missing_kvm_fails_preflight(tmp_path):
    result, _ = _run_harness(tmp_path, kvm_exists=False)

    assert result.returncode == 2
    assert "KVM" in result.stdout


def test_missing_sse_completion_is_a_hard_failure(tmp_path):
    result, _ = _run_harness(tmp_path, sse_complete=False)

    assert result.returncode == 1
    assert "run_completed" in result.stdout


def test_dirty_worktree_fails_before_any_api_mutation(tmp_path):
    result, _ = _run_harness(tmp_path, git_dirty=True)

    assert result.returncode == 2
    assert "clean" in result.stdout.lower()


def test_uploaded_specimen_digest_must_match_local_bytes(tmp_path):
    result, _ = _run_harness(tmp_path, specimen_sha_matches=False)

    assert result.returncode == 1
    assert "sha-256" in result.stdout.lower()


def test_complete_flow_writes_commit_bound_checksum_manifest(tmp_path):
    token = "must-not-be-written"
    result, output_dir = _run_harness(
        tmp_path,
        token=token,
        retain_output=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout
    assert (output_dir / "manifest.sha256").is_file()
    assert (output_dir / "git-commit.txt").read_text(encoding="utf-8").strip()
    combined = "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in output_dir.iterdir()
        if path.is_file()
    )
    assert token not in combined
