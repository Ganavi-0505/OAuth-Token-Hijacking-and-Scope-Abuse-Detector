"""
Algorithmic Risk Scoring Matrix
=================================
Evaluates OAuth app scope grants against a threat weight matrix.
Applies compounding mathematical penalty when:
  - App holds data modification rights (write scopes)
  - AND has offline_access (persistent token = attacker access survives logout)

Score bands:
  0  – 39  → LOW      (benign, no dangerous combos)
  40 – 69  → MEDIUM   (elevated, warrants review)
  70 – 89  → HIGH     (dangerous, revoke recommended)
  90 – 100 → CRITICAL (immediate eviction required)
"""

import json
import os

_rules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "risk_rules.json")

with open(_rules_path) as f:
    _rules = json.load(f)


def score(scopes: list) -> dict:
    """
    Core scoring function. Returns score, level, flags, and math breakdown.

    Args:
        scopes: List of OAuth scope strings granted to an app

    Returns:
        {
            "score":     int (0–100),
            "level":     str ("low" | "medium" | "high" | "critical"),
            "flags":     list of human-readable risk reasons,
            "breakdown": dict explaining how score was computed
        }
    """
    scope_set = set(scopes)
    flags          = []
    matched_scopes = set()
    best_combo     = 0

    # ── Step 1: Check dangerous combos ────────────────────────────────────────
    for combo in _rules["dangerous_combos"]:
        required = set(combo["scopes"])
        if required.issubset(scope_set):
            flags.append(combo["reason"])
            if combo["score"] > best_combo:
                best_combo = combo["score"]
            matched_scopes.update(required)

    # ── Step 2: Individual weights for unmatched scopes ───────────────────────
    leftover = scope_set - matched_scopes
    individual_total = sum(
        _rules["individual_weights"].get(s, 0)
        for s in leftover
    )
    # Small reduction to avoid double-counting with combos
    individual_contrib = max(0, individual_total - (10 if best_combo > 0 else 0))

    # ── Step 3: Compounding penalty (write + offline_access) ──────────────────
    penalty_cfg    = _rules["compounding_penalty"]
    has_persistence = bool(scope_set & set(penalty_cfg["modifier_scopes"]))
    has_write       = bool(scope_set & set(penalty_cfg["write_scopes"]))
    compound_penalty = penalty_cfg["penalty"] if (has_persistence and has_write) else 0

    if compound_penalty > 0:
        flags.append(
            f"Compounding penalty +{compound_penalty}: write-capable scope "
            f"combined with offline_access creates persistent exfiltration window"
        )

    # ── Step 4: Final score ───────────────────────────────────────────────────
    raw   = best_combo + individual_contrib + compound_penalty
    final = min(100, raw)

    level = (
        "critical" if final >= 90 else
        "high"     if final >= 70 else
        "medium"   if final >= 40 else
        "low"
    )

    if not flags:
        flags = ["No dangerous scope combinations detected"]

    return {
        "score":   final,
        "level":   level,
        "flags":   flags,
        "breakdown": {
            "combo_score":         best_combo,
            "individual_contrib":  individual_contrib,
            "compound_penalty":    compound_penalty,
            "raw_total":           raw,
            "capped_at_100":       raw > 100,
        }
    }


def level_color(level: str) -> str:
    """Bootstrap color class for a given risk level."""
    return {
        "critical": "danger",
        "high":     "warning",
        "medium":   "info",
        "low":      "success",
    }.get(level, "secondary")


def level_badge_class(level: str) -> str:
    return {
        "critical": "badge bg-danger",
        "high":     "badge bg-warning text-dark",
        "medium":   "badge bg-info text-dark",
        "low":      "badge bg-success",
    }.get(level, "badge bg-secondary")
