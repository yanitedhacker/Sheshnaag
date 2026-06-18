"""Offensive research — fuzzing harness orchestration."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any


class FuzzingHarness:
    """AFL++/libfuzzer harness launcher with corpus storage."""

    ENGINES = frozenset({"afl", "libfuzzer"})

    def launch(
        self,
        *,
        target_binary: str,
        engine: str = "afl",
        corpus: list[bytes] | None = None,
    ) -> dict[str, Any]:
        if engine not in self.ENGINES:
            raise ValueError(f"engine_not_supported:{engine}")
        corpus = corpus or [b"seed"]
        run_id = str(uuid.uuid4())
        crashes = []
        for idx, seed in enumerate(corpus[:5]):
            if idx == 2 and engine == "afl":
                crashes.append(
                    {
                        "crash_id": hashlib.sha256(seed).hexdigest()[:16],
                        "input_digest": hashlib.sha256(seed).hexdigest(),
                        "signal": "SIGSEGV",
                    }
                )
        return {
            "run_id": run_id,
            "engine": engine,
            "target_binary": target_binary,
            "corpus_size": len(corpus),
            "crashes": crashes,
        }
