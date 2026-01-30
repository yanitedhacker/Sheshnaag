"""SHAP-based explainability for risk predictions."""

import logging
from typing import Dict, Any, List, Optional

import numpy as np
import pandas as pd

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

from app.ml.risk_predictor import RiskPredictor
from app.ml.feature_engineering import FeatureEngineer

logger = logging.getLogger(__name__)


class RiskExplainer:
    """
    Provides explainability for risk predictions using SHAP values.
    
    Generates human-readable explanations for why a CVE has a particular risk score.
    """
    
    # Human-readable feature descriptions
    FEATURE_DESCRIPTIONS = {
        "cvss_v3_score": "CVSS v3 severity score",
        "has_exploit": "Public exploit code exists",
        "has_metasploit": "Metasploit module available",
        "has_poc": "Proof of concept published",
        "exploit_count": "Number of known exploits",
        "is_network_exploitable": "Exploitable over the network",
        "is_easy_exploit": "Low complexity, no privileges required",
        "is_critical": "Critical severity (CVSS >= 9.0)",
        "is_high_severity": "High severity (CVSS >= 7.0)",
        "has_critical_vendor": "Affects major vendor (Microsoft, Apache, etc.)",
        "product_count": "Number of affected products",
        "is_high_risk_cwe": "High-risk vulnerability type",
        "is_injection_cwe": "Injection vulnerability (SQL, Command, etc.)",
        "is_new_cve": "Recently published (< 30 days)",
        "text_remote_code_exec": "Description mentions remote code execution",
        "text_privilege_escalation": "Description mentions privilege escalation",
        "attack_vector": "Attack vector accessibility",
        "attack_complexity": "Attack complexity level",
        "days_since_published": "Days since CVE published",
    }
    
    def __init__(self, predictor: Optional[RiskPredictor] = None):
        self.predictor = predictor or RiskPredictor()
        self.explainer = None
        self.feature_engineer = FeatureEngineer()
    
    def initialize_explainer(self, background_data: Optional[pd.DataFrame] = None):
        """
        Initialize SHAP explainer with background data.
        
        Args:
            background_data: Reference data for SHAP (subset of training data)
        """
        if not SHAP_AVAILABLE:
            logger.warning("SHAP not available, using rule-based explanations")
            return
        
        if self.predictor.exploit_model is None:
            logger.warning("No model loaded, cannot initialize SHAP explainer")
            return
        
        if background_data is not None:
            # Use TreeExplainer for XGBoost
            self.explainer = shap.TreeExplainer(self.predictor.exploit_model)
        
        logger.info("SHAP explainer initialized")
    
    def explain_prediction(
        self,
        features: Dict[str, Any],
        risk_scores: Dict[str, Any],
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Generate explanation for a risk prediction.
        
        Args:
            features: Feature dictionary for the CVE
            risk_scores: Calculated risk scores
            top_k: Number of top features to include
            
        Returns:
            Dictionary with explanation components
        """
        explanation = {
            "top_features": [],
            "text_explanation": "",
            "risk_factors": [],
            "mitigating_factors": []
        }
        
        # Try SHAP-based explanation
        if SHAP_AVAILABLE and self.explainer is not None:
            explanation.update(self._shap_explanation(features, top_k))
        else:
            # Fall back to rule-based explanation
            explanation.update(self._rule_based_explanation(features, risk_scores, top_k))
        
        # Generate human-readable explanation
        explanation["text_explanation"] = self._generate_text_explanation(
            features, risk_scores, explanation
        )
        
        return explanation
    
    def _shap_explanation(
        self,
        features: Dict[str, Any],
        top_k: int
    ) -> Dict[str, Any]:
        """Generate SHAP-based feature importance."""
        # Prepare features
        X = pd.DataFrame([features])[self.predictor.feature_names]
        X_scaled = self.predictor.scaler.transform(X)
        
        # Calculate SHAP values
        shap_values = self.explainer.shap_values(X_scaled)
        
        if isinstance(shap_values, list):
            # For binary classification, use positive class
            shap_values = shap_values[1]
        
        # Get feature contributions
        feature_contributions = []
        for i, fname in enumerate(self.predictor.feature_names):
            contrib = shap_values[0, i]
            feature_contributions.append({
                "feature": fname,
                "contribution": float(contrib),
                "value": features.get(fname, 0),
                "description": self.FEATURE_DESCRIPTIONS.get(fname, fname)
            })
        
        # Sort by absolute contribution
        feature_contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
        
        # Separate positive and negative contributions
        risk_factors = [f for f in feature_contributions if f["contribution"] > 0]
        mitigating_factors = [f for f in feature_contributions if f["contribution"] < 0]
        
        return {
            "top_features": feature_contributions[:top_k],
            "risk_factors": risk_factors[:top_k],
            "mitigating_factors": mitigating_factors[:3]
        }
    
    def _rule_based_explanation(
        self,
        features: Dict[str, Any],
        risk_scores: Dict[str, Any],
        top_k: int
    ) -> Dict[str, Any]:
        """Generate rule-based feature importance when SHAP unavailable."""
        risk_factors = []
        mitigating_factors = []
        
        # Check each important feature
        feature_checks = [
            ("has_exploit", 0.30, "Public exploit code is available"),
            ("has_metasploit", 0.15, "Metasploit module exists for this vulnerability"),
            ("is_critical", 0.20, "Critical severity vulnerability (CVSS >= 9.0)"),
            ("is_high_severity", 0.15, "High severity vulnerability (CVSS >= 7.0)"),
            ("is_network_exploitable", 0.10, "Can be exploited remotely over network"),
            ("is_easy_exploit", 0.15, "Low attack complexity, no privileges required"),
            ("has_critical_vendor", 0.10, "Affects widely-used software"),
            ("is_high_risk_cwe", 0.10, "High-risk vulnerability category"),
            ("is_new_cve", 0.05, "Recently published vulnerability"),
            ("text_remote_code_exec", 0.10, "Enables remote code execution"),
        ]
        
        for fname, weight, description in feature_checks:
            value = features.get(fname, 0)
            if value:
                risk_factors.append({
                    "feature": fname,
                    "contribution": weight,
                    "value": value,
                    "description": description
                })
        
        # Check mitigating factors
        if features.get("user_interaction", 0) == 1:  # REQUIRED
            mitigating_factors.append({
                "feature": "user_interaction",
                "contribution": -0.10,
                "value": 1,
                "description": "Requires user interaction to exploit"
            })
        
        if features.get("attack_complexity", 0) == 1:  # HIGH
            mitigating_factors.append({
                "feature": "attack_complexity",
                "contribution": -0.10,
                "value": 1,
                "description": "High attack complexity required"
            })
        
        if features.get("privileges_required", 0) == 1:  # HIGH
            mitigating_factors.append({
                "feature": "privileges_required",
                "contribution": -0.08,
                "value": 1,
                "description": "High privileges required to exploit"
            })
        
        # Sort and limit
        risk_factors.sort(key=lambda x: x["contribution"], reverse=True)
        
        return {
            "top_features": risk_factors[:top_k],
            "risk_factors": risk_factors[:top_k],
            "mitigating_factors": mitigating_factors[:3]
        }
    
    def _generate_text_explanation(
        self,
        features: Dict[str, Any],
        risk_scores: Dict[str, Any],
        explanation: Dict[str, Any]
    ) -> str:
        """Generate human-readable text explanation."""
        risk_level = risk_scores.get("risk_level", "UNKNOWN")
        overall_score = risk_scores.get("overall_score", 0)
        exploit_prob = risk_scores.get("exploit_probability", 0)
        
        # Build explanation text
        text_parts = []
        
        # Opening statement
        text_parts.append(
            f"This vulnerability is rated as {risk_level} risk "
            f"with a score of {overall_score:.1f}/100."
        )
        
        # Exploit probability
        if exploit_prob >= 0.7:
            text_parts.append(
                f"There is a HIGH likelihood ({exploit_prob:.0%}) of active exploitation."
            )
        elif exploit_prob >= 0.4:
            text_parts.append(
                f"There is a MODERATE likelihood ({exploit_prob:.0%}) of exploitation."
            )
        else:
            text_parts.append(
                f"The likelihood of exploitation is relatively LOW ({exploit_prob:.0%})."
            )
        
        # Top risk factors
        risk_factors = explanation.get("risk_factors", [])
        if risk_factors:
            factors_text = ", ".join([
                f["description"].lower() for f in risk_factors[:3]
            ])
            text_parts.append(f"Key risk factors: {factors_text}.")
        
        # Mitigating factors
        mitigating = explanation.get("mitigating_factors", [])
        if mitigating:
            mit_text = ", ".join([
                f["description"].lower() for f in mitigating[:2]
            ])
            text_parts.append(f"Mitigating factors: {mit_text}.")
        
        # Recommendation based on risk level
        if risk_level == "CRITICAL":
            text_parts.append("RECOMMENDATION: Patch immediately or implement compensating controls.")
        elif risk_level == "HIGH":
            text_parts.append("RECOMMENDATION: Prioritize patching within 7 days.")
        elif risk_level == "MEDIUM":
            text_parts.append("RECOMMENDATION: Schedule patching within 30 days.")
        else:
            text_parts.append("RECOMMENDATION: Address during regular maintenance cycle.")
        
        return " ".join(text_parts)
    
    def get_batch_explanations(
        self,
        cve_features: List[Dict[str, Any]],
        risk_scores: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate explanations for multiple CVEs."""
        explanations = []
        
        for features, scores in zip(cve_features, risk_scores):
            exp = self.explain_prediction(features, scores)
            explanations.append(exp)
        
        return explanations
