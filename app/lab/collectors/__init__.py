"""Evidence collectors package (Pod D)."""

from app.lab.collectors.registry import COLLECTOR_REGISTRY, default_collectors, instantiate_collectors

__all__ = [
    "COLLECTOR_REGISTRY",
    "default_collectors",
    "instantiate_collectors",
]
