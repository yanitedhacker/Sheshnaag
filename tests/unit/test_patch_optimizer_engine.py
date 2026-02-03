import pytest

from app.patch_optimizer.engine import PatchOptimizer


@pytest.mark.unit
def test_optimizer_compute_decisions_accepts_delay_days(monkeypatch):
    """
    Smoke test: engine supports delay_days knob without raising.
    """
    class _FakeSession:
        def query(self, *_args, **_kwargs):
            raise AssertionError("DB should not be hit in this stubbed test")

    opt = PatchOptimizer(_FakeSession())
    monkeypatch.setattr(opt, "list_patches", lambda: [])
    assert opt.compute_decisions(delay_days=0) == []
    assert opt.compute_decisions(delay_days=30) == []

