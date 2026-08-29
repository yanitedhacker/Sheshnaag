#!/usr/bin/env python3
"""Report the external-worker gate for Tracee runtime evidence."""

from __future__ import annotations

import os
import subprocess


def docker_ready() -> bool:
    try:
        result = subprocess.run(["docker", "version"], capture_output=True, text=True, timeout=15)
        return result.returncode == 0
    except Exception:
        return False


def image_present(image: str) -> bool:
    try:
        result = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True, timeout=15)
        return result.returncode == 0
    except Exception:
        return False


def main() -> int:
    if not docker_ready():
        print("SKIP: docker daemon unavailable; Tracee smoke not run.")
        return 0

    image = os.environ.get("SHESHNAAG_TRACEE_IMAGE", "sheshnaag-kali-tracee:2026.1")
    if not image_present(image):
        print(f"SKIP: Tracee-capable image {image} is not present. Run scripts/build_sheshnaag_tracee_image.sh first.")
        return 0

    print(
        "SKIP: Tracee image packaging is present, but runtime evidence requires "
        "a separately managed disposable Linux worker. The docker_kali provider "
        "does not request privileged host-kernel access."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
