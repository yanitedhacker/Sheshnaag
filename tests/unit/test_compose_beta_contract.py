"""Rendered Docker Compose contract for beta runtime configuration."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]

COMPOSE_ENV = {
    "POSTGRES_PASSWORD": "test-postgres-password",
    "REDIS_PASSWORD": "test-redis-password",
    "MINIO_ROOT_PASSWORD": "test-minio-password",
    "SECRET_KEY": "test-secret-key",
    "SIGNING_KEY_DIR": "/app/data/signing_keys",
    "ANTHROPIC_API_KEY": "anthropic-placeholder",
    "ANTHROPIC_BASE_URL": "https://anthropic.invalid",
    "ANTHROPIC_MODEL": "claude-test",
    "OPENAI_API_KEY": "openai-placeholder",
    "OPENAI_BASE_URL": "https://openai.invalid/v1",
    "OPENAI_MODEL": "gpt-test",
    "OPENAI_ORG": "org-test",
    "GOOGLE_API_KEY": "google-placeholder",
    "GEMINI_API_KEY": "gemini-placeholder",
    "GEMINI_BASE_URL": "https://gemini.invalid",
    "GEMINI_MODEL": "gemini-test",
    "AZURE_OPENAI_API_KEY": "azure-placeholder",
    "AZURE_OPENAI_ENDPOINT": "https://azure.invalid",
    "AZURE_OPENAI_DEPLOYMENT": "deployment-test",
    "AZURE_OPENAI_MODEL": "azure-model-test",
    "AZURE_OPENAI_API_VERSION": "2026-01-01",
    "AWS_ACCESS_KEY_ID": "aws-access-placeholder",
    "AWS_SECRET_ACCESS_KEY": "aws-secret-placeholder",
    "AWS_SESSION_TOKEN": "aws-session-placeholder",
    "AWS_PROFILE": "beta-test",
    "AWS_REGION": "ap-south-1",
    "AWS_DEFAULT_REGION": "ap-south-1",
    "BEDROCK_MODEL_ID": "bedrock-test",
    "OLLAMA_HOST": "http://ollama.invalid",
    "VLLM_HOST": "http://vllm.invalid",
    "LOCAL_AI_MODEL": "local-test",
    "LOCAL_AI_API_KEY": "local-placeholder",
    "SHESHNAAG_EMBEDDING_PROVIDER": "openai",
    "SHESHNAAG_EMBEDDING_MODEL": "embedding-test",
    "AUTONOMOUS_AGENT_PROVIDER": "anthropic",
    "ATTACK_MAPPER_LLM_FALLBACK": "1",
    "ATTACK_MAPPER_LLM_PROVIDER": "openai",
    "BRIEF_LLM_PROVIDER": "gemini",
    "SHESHNAAG_EGRESS_ENFORCE": "1",
    "SHESHNAAG_ENABLE_PCAP": "1",
    "SHESHNAAG_REQUIRE_MEMORY_DUMP": "1",
}

AI_PROVIDER_ENV = {
    key: value
    for key, value in COMPOSE_ENV.items()
    if key
    in {
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_MODEL",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_MODEL",
        "OPENAI_ORG",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "GEMINI_BASE_URL",
        "GEMINI_MODEL",
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_DEPLOYMENT",
        "AZURE_OPENAI_MODEL",
        "AZURE_OPENAI_API_VERSION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "BEDROCK_MODEL_ID",
        "OLLAMA_HOST",
        "VLLM_HOST",
        "LOCAL_AI_MODEL",
        "LOCAL_AI_API_KEY",
        "SHESHNAAG_EMBEDDING_PROVIDER",
        "SHESHNAAG_EMBEDDING_MODEL",
        "AUTONOMOUS_AGENT_PROVIDER",
        "ATTACK_MAPPER_LLM_FALLBACK",
        "ATTACK_MAPPER_LLM_PROVIDER",
        "BRIEF_LLM_PROVIDER",
    }
}


def _render_compose(tmp_path: Path) -> dict:
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI is not installed")

    env_file = tmp_path / "compose.env"
    env_file.write_text(
        "".join(f"{key}={value}\n" for key, value in COMPOSE_ENV.items()),
        encoding="utf-8",
    )

    process_env = os.environ.copy()
    for key in COMPOSE_ENV:
        process_env.pop(key, None)
    process_env.pop("COMPOSE_FILE", None)
    process_env.pop("COMPOSE_PROFILES", None)

    result = subprocess.run(
        [
            "docker",
            "compose",
            "--file",
            str(ROOT / "docker-compose.yml"),
            "--env-file",
            str(env_file),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=process_env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_compose_routes_ai_provider_configuration_only_to_api(tmp_path):
    rendered = _render_compose(tmp_path)
    api_env = rendered["services"]["api"]["environment"]
    worker_env = rendered["services"]["worker"]["environment"]

    assert {key: api_env.get(key) for key in AI_PROVIDER_ENV} == AI_PROVIDER_ENV
    assert set(AI_PROVIDER_ENV).isdisjoint(worker_env)


def test_compose_propagates_beta_runtime_safety_flags(tmp_path):
    rendered = _render_compose(tmp_path)

    expected = {
        "SHESHNAAG_EGRESS_ENFORCE": "1",
        "SHESHNAAG_ENABLE_PCAP": "1",
        "SHESHNAAG_REQUIRE_MEMORY_DUMP": "1",
    }
    for service_name in ("api", "worker"):
        service_env = rendered["services"][service_name]["environment"]
        assert {key: service_env.get(key) for key in expected} == expected
