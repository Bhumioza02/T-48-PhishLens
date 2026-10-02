"""
PhishLens - Deterministic Risk Engine
Calculates risk scores and security verdicts (SAFE / CAUTION / DANGER).
CRITICAL: Verdicts are purely rule-based and transparent; never reliant solely on an LLM.
"""
from typing import Dict, Any, List
from config import (
    VERDICT_SAFE,
    VERDICT_CAUTION,
    VERDICT_DANGER,
    RISK_THRESHOLD_SAFE,
    RISK_THRESHOLD_DANGER
)

def evaluate_risk(risk_score: int, flags: List[str]) -> Dict[str, Any]:
    """
    Evaluates aggregated risk score and flags to produce the final security verdict.
    """
    if risk_score >= RISK_THRESHOLD_DANGER:
        verdict = VERDICT_DANGER
    elif risk_score > RISK_THRESHOLD_SAFE:
        verdict = VERDICT_CAUTION
    else:
        verdict = VERDICT_SAFE

    return {
        "verdict": verdict,
        "risk_score": min(max(risk_score, 0), 100),
        "flags": flags,
    }
