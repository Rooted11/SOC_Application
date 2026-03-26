from __future__ import annotations

from typing import List, Tuple

from sqlalchemy.orm import Session

from .database import DetectionRule


def evaluate_rules(db: Session, log_dict: dict) -> Tuple[List[int], bool]:
    """
    Very lightweight rule evaluation:
    - match by event_type or source if present in rule.conditions
    - allow static enable/disable
    Returns (matched_rule_ids, is_suppressed)
    """
    matches: list[int] = []
    suppressed = False
    rules = db.query(DetectionRule).filter(DetectionRule.enabled == True).all()
    for rule in rules:
        cond = rule.conditions or {}
        evt_ok = ("event_type" not in cond) or cond.get("event_type") == log_dict.get("event_type")
        src_ok = ("source" not in cond) or cond.get("source") == log_dict.get("source")
        ip_ok = True
        if "ip_src" in cond and cond["ip_src"] != log_dict.get("ip_src"):
            ip_ok = False
        if not (evt_ok and src_ok and ip_ok):
            continue
        # suppression check
        suppression = rule.suppression or {}
        if suppression:
            if log_dict.get("ip_src") in suppression.get("ips", []):
                suppressed = True
                continue
        matches.append(rule.id)
    return matches, suppressed
