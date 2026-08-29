from scripts import sheshnaag_smoke_worker


def test_process_queued_run_consumes_matching_message_and_requires_completion(monkeypatch):
    worker_calls = []

    class FakeBus:
        def subscribe(self, stream, *, last_id, block_ms):
            assert stream == sheshnaag_smoke_worker.SANDBOX_WORK_STREAM
            assert last_id == "0-0"
            assert block_ms == 10
            yield {"run_id": 7, "tenant_id": 3}

    published_bus = FakeBus()

    class FakeWorker:
        SessionLocal = None

        @staticmethod
        def process_sandbox_work(message, *, bus):
            worker_calls.append((message, bus))
            return {"run_id": 7, "status": "completed", "result": {"evidence_count": 2}}

    monkeypatch.setattr(sheshnaag_smoke_worker, "EventBus", lambda: published_bus)
    monkeypatch.setattr(sheshnaag_smoke_worker, "sandbox_worker", FakeWorker)

    session_factory = object()
    result = sheshnaag_smoke_worker.process_queued_run(
        run={"id": 7, "state": "queued"},
        session_factory=session_factory,
    )

    assert FakeWorker.SessionLocal is session_factory
    assert result["result"]["evidence_count"] == 2
    assert worker_calls == [({"run_id": 7, "tenant_id": 3}, published_bus)]
