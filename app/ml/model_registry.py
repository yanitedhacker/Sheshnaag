"""Singleton model loader and registry for ML inference."""

from __future__ import annotations

import logging
from typing import Optional

from app.ml.risk_predictor import RiskPredictor
from app.ml.explainer import RiskExplainer

logger = logging.getLogger(__name__)

_predictor: Optional[RiskPredictor] = None
_explainer: Optional[RiskExplainer] = None


def get_predictor() -> RiskPredictor:
    global _predictor
    if _predictor is None:
        _predictor = RiskPredictor()
        _predictor.load_model()
    return _predictor


def get_explainer() -> RiskExplainer:
    global _explainer
    if _explainer is None:
        predictor = get_predictor()
        _explainer = RiskExplainer(predictor)
        _explainer.initialize_explainer()
    return _explainer


def preload_models():
    """Preload models at application startup."""
    predictor = get_predictor()
    explainer = get_explainer()
    logger.info("Model registry initialized (model=%s, explainer=%s)", bool(predictor.exploit_model), bool(explainer))
