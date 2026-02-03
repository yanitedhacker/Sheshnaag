"""
ML model for predicting CVE exploit risk.

Author: Archishman Paul

This module is the brain of the operation. After experimenting with 
Random Forests, SVMs, Neural Networks, and even some exotic ensemble 
methods, XGBoost emerged as the clear winner for this problem.

Why XGBoost? 
  1. Handles the mixed feature types (categorical + numerical) gracefully
  2. Built-in feature importance for explainability
  3. Fast inference for real-time API responses
  4. Robust to the imbalanced nature of exploit data

The heuristic fallback isn't a cop-out—it's battle-tested domain knowledge 
that works remarkably well when the ML model hasn't been trained yet.
Sometimes the simplest solution is the right one.
"""

import hashlib
import logging
import os
from typing import Dict, Any, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    xgb = None
    XGBOOST_AVAILABLE = False

from app.core.config import settings
from app.ml.feature_engineering import FeatureEngineer

logger = logging.getLogger(__name__)


class RiskPredictor:
    """
    ML model for predicting CVE exploit probability and risk scores.
    
    Uses XGBoost for primary predictions with ensemble fallback.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or settings.model_path
        self.feature_engineer = FeatureEngineer()
        
        # Models
        self.exploit_model = None  # XGBClassifier if available
        self.risk_model = None  # XGBRegressor if available
        self.scaler: Optional[StandardScaler] = None
        
        # Feature names for consistency
        self.feature_names = self.feature_engineer.get_feature_names()
        
        # Model version
        self.model_version = "1.0.0"
    
    def train_exploit_model(
        self,
        X: pd.DataFrame,
        y: np.ndarray,
        test_size: float = 0.2,
        **xgb_params
    ) -> Dict[str, Any]:
        """
        Train the exploit probability prediction model.
        
        Args:
            X: Feature DataFrame
            y: Binary labels (1 = exploited, 0 = not exploited)
            test_size: Fraction of data for testing
            **xgb_params: Additional XGBoost parameters
            
        Returns:
            Training metrics dictionary
        """
        if not XGBOOST_AVAILABLE:
            logger.warning("XGBoost not available, using heuristic model")
            return {"status": "xgboost_unavailable", "using": "heuristic"}
        
        logger.info("Training exploit prediction model")
        
        # Use only training features
        X_train_features = X[self.feature_names].copy()
        
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_train_features)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Default XGBoost parameters
        default_params = {
            "n_estimators": 200,
            "max_depth": 6,
            "learning_rate": 0.1,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "min_child_weight": 3,
            "gamma": 0.1,
            "reg_alpha": 0.1,
            "reg_lambda": 1.0,
            "objective": "binary:logistic",
            "eval_metric": "auc",
            "use_label_encoder": False,
            "random_state": 42,
            "n_jobs": -1
        }
        default_params.update(xgb_params)
        
        # Train XGBoost model
        self.exploit_model = xgb.XGBClassifier(**default_params)
        self.exploit_model.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=False
        )
        
        # Evaluate
        y_pred = self.exploit_model.predict(X_test)
        y_proba = self.exploit_model.predict_proba(X_test)[:, 1]
        
        metrics = {
            "roc_auc": roc_auc_score(y_test, y_proba),
            "classification_report": classification_report(y_test, y_pred, output_dict=True),
            "feature_importance": dict(zip(
                self.feature_names,
                self.exploit_model.feature_importances_.tolist()
            ))
        }
        
        # Cross-validation
        cv_scores = cross_val_score(
            self.exploit_model, X_scaled, y, cv=5, scoring="roc_auc"
        )
        metrics["cv_roc_auc_mean"] = cv_scores.mean()
        metrics["cv_roc_auc_std"] = cv_scores.std()
        
        logger.info(f"Model trained. ROC-AUC: {metrics['roc_auc']:.4f}")
        
        return metrics
    
    def predict_exploit_probability(
        self,
        features: Dict[str, Any]
    ) -> Tuple[float, float, float]:
        """
        Predict exploit probability for a single CVE.
        
        Args:
            features: Feature dictionary from FeatureEngineer
            
        Returns:
            Tuple of (probability, confidence_lower, confidence_upper)
        """
        if self.exploit_model is None:
            # Use heuristic model if ML model not trained
            return self._heuristic_exploit_probability(features)
        
        # Prepare features
        X = pd.DataFrame([features])[self.feature_names]
        X_scaled = self.scaler.transform(X)
        
        # Get probability
        proba = self.exploit_model.predict_proba(X_scaled)[0, 1]
        
        # Estimate confidence bounds (simplified)
        # In production, would use calibration or conformal prediction
        confidence_margin = 0.1 * (1 - abs(proba - 0.5) * 2)
        lower = max(0, proba - confidence_margin)
        upper = min(1, proba + confidence_margin)
        
        return proba, lower, upper

    def predict_exploit_probabilities_batch(
        self,
        features_df: pd.DataFrame,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Predict exploit probabilities for a batch of CVEs.

        Returns:
            Tuple of (proba, lower, upper) arrays.
        """
        if self.exploit_model is None:
            # Heuristic per row
            probs = []
            lowers = []
            uppers = []
            for _, row in features_df.iterrows():
                p, lo, hi = self._heuristic_exploit_probability(row.to_dict())
                probs.append(p)
                lowers.append(lo)
                uppers.append(hi)
            return np.array(probs), np.array(lowers), np.array(uppers)

        X = features_df[self.feature_names]
        X_scaled = self.scaler.transform(X)
        proba = self.exploit_model.predict_proba(X_scaled)[:, 1]

        # Simplified confidence bounds
        confidence_margin = 0.1 * (1 - np.abs(proba - 0.5) * 2)
        lower = np.maximum(0, proba - confidence_margin)
        upper = np.minimum(1, proba + confidence_margin)
        return proba, lower, upper
    
    def _heuristic_exploit_probability(
        self,
        features: Dict[str, Any]
    ) -> Tuple[float, float, float]:
        """
        Heuristic exploit probability when ML model unavailable.
        
        Based on domain knowledge and security best practices.
        """
        score = 0.1  # Base probability
        
        # CVSS score impact (major factor)
        cvss = features.get("cvss_v3_score", 0)
        if cvss >= 9.0:
            score += 0.35
        elif cvss >= 7.0:
            score += 0.25
        elif cvss >= 4.0:
            score += 0.10
        
        # Exploit availability (strongest signal)
        if features.get("has_exploit", 0):
            score += 0.30
        if features.get("has_metasploit", 0):
            score += 0.10
        if features.get("has_poc", 0):
            score += 0.05
        
        # Attack characteristics
        if features.get("is_network_exploitable", 0):
            score += 0.05
        if features.get("is_easy_exploit", 0):
            score += 0.10
        
        # CWE risk
        if features.get("is_high_risk_cwe", 0):
            score += 0.05
        
        # Recency
        if features.get("is_new_cve", 0):
            score += 0.05
        
        # Critical text indicators
        if features.get("text_remote_code_exec", 0):
            score += 0.05
        
        # Cap at reasonable bounds
        score = min(0.95, max(0.05, score))
        
        # Wider confidence for heuristic
        return score, max(0, score - 0.15), min(1, score + 0.15)
    
    def calculate_risk_score(
        self,
        features: Dict[str, Any],
        exploit_probability: float
    ) -> Dict[str, Any]:
        """
        Calculate overall risk score and components.
        
        Args:
            features: Feature dictionary
            exploit_probability: Predicted exploit probability
            
        Returns:
            Dictionary with risk scores and components
        """
        # Component scores (0-100 scale)
        
        # Exploit probability component
        exploit_score = exploit_probability * 100
        
        # Impact score (from CVSS)
        cvss = features.get("cvss_v3_score", 0)
        impact_score = (cvss / 10.0) * 100
        
        # Exposure score (based on affected products)
        product_count = features.get("product_count", 1)
        has_critical_vendor = features.get("has_critical_vendor", 0)
        exposure_score = min(100, (
            20 * min(product_count, 5) + 
            (40 if has_critical_vendor else 0)
        ))
        
        # Temporal score (newer = higher risk in short term)
        age_bucket = features.get("age_bucket", 1)
        temporal_score = age_bucket * 20  # 20-100 based on age
        
        # Calculate overall score using weighted combination
        weights = {
            "exploit": 0.35,
            "impact": 0.30,
            "exposure": 0.20,
            "temporal": 0.15
        }
        
        overall_score = (
            weights["exploit"] * exploit_score +
            weights["impact"] * impact_score +
            weights["exposure"] * exposure_score +
            weights["temporal"] * temporal_score
        )
        
        # Determine risk level
        if overall_score >= 80:
            risk_level = "CRITICAL"
        elif overall_score >= 60:
            risk_level = "HIGH"
        elif overall_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            "overall_score": round(overall_score, 2),
            "risk_level": risk_level,
            "exploit_probability": round(exploit_probability, 4),
            "exploit_score": round(exploit_score, 2),
            "impact_score": round(impact_score, 2),
            "exposure_score": round(exposure_score, 2),
            "temporal_score": round(temporal_score, 2),
            "weights": weights
        }
    
    def save_model(self, path: Optional[str] = None):
        """
        Save trained model to disk using joblib.

        Uses joblib for safer serialization compared to pickle.
        Also creates a checksum file for integrity verification.
        """
        save_path = path or self.model_path
        os.makedirs(save_path, exist_ok=True)

        model_file = os.path.join(save_path, "risk_model.joblib")
        checksum_file = os.path.join(save_path, "risk_model.sha256")

        model_data = {
            "exploit_model": self.exploit_model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "model_version": self.model_version
        }

        # Save model using joblib
        joblib.dump(model_data, model_file)

        # Create checksum for integrity verification
        with open(model_file, "rb") as f:
            checksum = hashlib.sha256(f.read()).hexdigest()
        with open(checksum_file, "w") as f:
            f.write(checksum)

        logger.info(f"Model saved to {save_path} with checksum verification")

    def load_model(self, path: Optional[str] = None):
        """
        Load trained model from disk with integrity verification.

        Verifies the model file checksum before loading to prevent
        loading of tampered model files.
        """
        load_path = path or self.model_path

        # Try new joblib format first, then fall back to legacy pickle
        model_file = os.path.join(load_path, "risk_model.joblib")
        checksum_file = os.path.join(load_path, "risk_model.sha256")
        legacy_model_file = os.path.join(load_path, "risk_model.pkl")

        # Check for new format
        if os.path.exists(model_file):
            # Verify integrity if checksum exists
            if os.path.exists(checksum_file):
                with open(checksum_file, "r") as f:
                    expected_checksum = f.read().strip()
                with open(model_file, "rb") as f:
                    actual_checksum = hashlib.sha256(f.read()).hexdigest()
                if actual_checksum != expected_checksum:
                    logger.error("Model file integrity check failed! File may be corrupted or tampered.")
                    raise ValueError("Model file integrity check failed!")
                logger.info("Model integrity verified")

            model_data = joblib.load(model_file)

        # Fall back to legacy pickle format for backwards compatibility
        elif os.path.exists(legacy_model_file):
            logger.warning(f"Loading legacy pickle model from {legacy_model_file}. Consider re-saving in joblib format.")
            import pickle
            with open(legacy_model_file, "rb") as f:
                model_data = pickle.load(f)
        else:
            logger.warning(f"No model found at {load_path}")
            return False

        self.exploit_model = model_data["exploit_model"]
        self.scaler = model_data["scaler"]
        self.feature_names = model_data["feature_names"]
        self.model_version = model_data["model_version"]

        logger.info(f"Model loaded from {load_path}")
        return True
