"""
Correlation Engine — detects multi-event attack patterns across logs.

Each correlation rule is a declarative data structure (not hardcoded logic)
describing a sequence or cluster of events that, when observed within a time
window, indicates a higher-level threat.  The engine is invoked after every
log insert so it can react in near-real-time.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import and_
from sqlalchemy.orm import Session

from .database import Incident, Log, SeverityEnum, StatusEnum

logger = logging.getLogger(__name__)


# ── Rule definitions ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CorrelationRule:
    """
    Declarative description of a multi-event correlation pattern.

    Attributes:
        name:                Human-readable rule name.
        description:         What this rule detects.
        severity:            SeverityEnum value assigned to resulting incidents.
        event_types:         Ordered list of event_type values to match.
                             The *last* type is the "trigger" event; earlier
                             types form the precursor window.
        time_window_minutes: Maximum span (in minutes) between the first and
                             last matching event.
        threshold:           Minimum number of precursor events required.
        group_by:            Log fields whose values must be identical across
                             matched events (e.g. "ip_src", "user").
        distinct_field:      Optional field that must have N distinct values
                             among precursor events (e.g. "ip_dst" for lateral
                             movement).  When set, *threshold* applies to
                             the distinct count of this field instead of the
                             raw event count.
    """
    name: str
    description: str
    severity: SeverityEnum
    event_types: list[str]
    time_window_minutes: int
    threshold: int
    group_by: list[str]
    distinct_field: Optional[str] = None


# All built-in correlation rules.  Additional rules can be appended at
# runtime or loaded from the database; the engine treats this list as the
# single source of truth.

CORRELATION_RULES: list[CorrelationRule] = [

    # 1. Brute Force -> Success
    #    5+ auth_failure from the same source IP followed by auth_success
    #    within 10 minutes.
    CorrelationRule(
        name="Brute Force → Success",
        description=(
            "Multiple authentication failures followed by a successful login "
            "from the same source IP — possible credential compromise."
        ),
        severity=SeverityEnum.high,
        event_types=["auth_failure", "auth_success"],
        time_window_minutes=10,
        threshold=5,
        group_by=["ip_src"],
    ),

    # 2. Lateral Movement Chain
    #    Successful logins from one IP to 3+ distinct destination IPs within
    #    15 minutes.
    CorrelationRule(
        name="Lateral Movement Chain",
        description=(
            "An authenticated source IP contacted multiple distinct "
            "destinations — indicative of lateral movement."
        ),
        severity=SeverityEnum.high,
        event_types=["auth_success"],
        time_window_minutes=15,
        threshold=3,
        group_by=["ip_src"],
        distinct_field="ip_dst",
    ),

    # 3. Privilege Escalation After Login
    #    auth_success followed by privilege_escalation by the same user
    #    within 5 minutes.
    CorrelationRule(
        name="Privilege Escalation After Login",
        description=(
            "A user escalated privileges shortly after authenticating — "
            "may indicate credential abuse or exploitation."
        ),
        severity=SeverityEnum.critical,
        event_types=["auth_success", "privilege_escalation"],
        time_window_minutes=5,
        threshold=1,
        group_by=["user"],
    ),

    # 4. Port Scan Detection
    #    10+ firewall events from the same source IP hitting different
    #    destination ports within 5 minutes.
    CorrelationRule(
        name="Port Scan Detection",
        description=(
            "A single source IP generated firewall events against many "
            "distinct destination ports — network reconnaissance likely."
        ),
        severity=SeverityEnum.medium,
        event_types=["firewall_event"],
        time_window_minutes=5,
        threshold=10,
        group_by=["ip_src"],
        distinct_field="ip_dst",  # ip_dst often encodes host:port in logs
    ),

    # 5. C2 Beaconing
    #    3+ c2_beacon events from the same source IP within 30 minutes.
    CorrelationRule(
        name="C2 Beaconing",
        description=(
            "Repeated command-and-control beacon signals detected from a "
            "single host — possible active C2 channel."
        ),
        severity=SeverityEnum.critical,
        event_types=["c2_beacon"],
        time_window_minutes=30,
        threshold=3,
        group_by=["ip_src"],
    ),

    # 6. Data Exfiltration After Compromise
    #    auth_failure / auth_success followed by data_exfiltration from the
    #    same source IP within 60 minutes.
    CorrelationRule(
        name="Data Exfiltration After Compromise",
        description=(
            "Data exfiltration was observed from an IP that recently had "
            "authentication activity — potential data breach in progress."
        ),
        severity=SeverityEnum.critical,
        event_types=["auth_failure", "auth_success", "data_exfiltration"],
        time_window_minutes=60,
        threshold=1,
        group_by=["ip_src"],
    ),
]


# ── Core evaluation logic ─────────────────────────────────────────────────────

def _build_group_key(log: Log, group_by: list[str]) -> Optional[tuple]:
    """
    Extract the grouping key from a Log row.  Returns None when any of the
    required fields is missing (the log cannot participate in this rule).
    """
    parts: list[str] = []
    for field_name in group_by:
        value = getattr(log, field_name, None)
        if value is None:
            return None
        parts.append(str(value))
    return tuple(parts)


def _group_key_from_dict(log_dict: dict, group_by: list[str]) -> Optional[tuple]:
    """Same as _build_group_key but operates on the raw dict payload."""
    parts: list[str] = []
    for field_name in group_by:
        value = log_dict.get(field_name)
        if value is None:
            return None
        parts.append(str(value))
    return tuple(parts)


def _evaluate_single_rule(
    db: Session,
    rule: CorrelationRule,
    current_log: dict,
) -> Optional[dict]:
    """
    Evaluate one correlation rule against the current log and the recent
    history stored in the database.

    Returns a correlation result dict when the rule fires, or None.
    """

    current_event_type = current_log.get("event_type") or "unknown"

    # ── Determine if the current log is relevant to this rule ────────────
    # For sequence rules the trigger event is the LAST type in event_types.
    # For cluster rules (single event_type list) any matching event counts.
    trigger_types = {rule.event_types[-1]}
    precursor_types = set(rule.event_types[:-1]) if len(rule.event_types) > 1 else set(rule.event_types)

    # If this log's event_type is not the trigger, skip immediately.
    if current_event_type not in trigger_types:
        return None

    # ── Build the group key for the current log ─────────────────────────
    group_key = _group_key_from_dict(current_log, rule.group_by)
    if group_key is None:
        return None

    # ── Query precursor events from the DB ──────────────────────────────
    window_start = datetime.utcnow() - timedelta(minutes=rule.time_window_minutes)

    # Build dynamic filter for group_by fields.
    group_filters = []
    for idx, field_name in enumerate(rule.group_by):
        column = getattr(Log, field_name, None)
        if column is not None:
            group_filters.append(column == group_key[idx])

    # For sequence rules we look for precursor event types.
    # For single-type cluster rules, precursor == trigger.
    search_types = precursor_types if precursor_types else trigger_types

    query = (
        db.query(Log)
        .filter(
            and_(
                Log.event_type.in_(search_types),
                Log.timestamp >= window_start,
                *group_filters,
            )
        )
        .order_by(Log.timestamp.asc())
    )

    precursor_logs: list[Log] = query.all()

    # ── Apply threshold / distinct logic ─────────────────────────────────
    if rule.distinct_field:
        # Count distinct values of the specified field.
        distinct_values: set[str] = set()
        for log_row in precursor_logs:
            val = getattr(log_row, rule.distinct_field, None)
            if val is not None:
                distinct_values.add(str(val))
        match_count = len(distinct_values)
    else:
        match_count = len(precursor_logs)

    if match_count < rule.threshold:
        return None

    # ── Rule fired — build the result ────────────────────────────────────
    matched_ids = [log_row.id for log_row in precursor_logs]
    group_key_str = ", ".join(
        f"{field}={val}" for field, val in zip(rule.group_by, group_key)
    )

    evidence_lines = [
        f"Rule:       {rule.name}",
        f"Window:     {rule.time_window_minutes} min",
        f"Group:      {group_key_str}",
        f"Threshold:  {rule.threshold}",
        f"Observed:   {match_count}",
    ]
    if rule.distinct_field:
        evidence_lines.append(f"Distinct {rule.distinct_field} values: {match_count}")
    evidence_lines.append(f"Matched log IDs: {matched_ids}")

    logger.info(
        "Correlation rule '%s' fired for group [%s] — %d events matched (threshold %d)",
        rule.name,
        group_key_str,
        match_count,
        rule.threshold,
    )

    return {
        "rule_name":        rule.name,
        "description":      rule.description,
        "severity":         rule.severity,
        "matched_log_ids":  matched_ids,
        "group_key":        group_key_str,
        "evidence_summary": "\n".join(evidence_lines),
    }


# ── Public API ────────────────────────────────────────────────────────────────

_CORR_DEDUP_MINUTES = 30


def evaluate_correlations(db: Session, log_dict: dict) -> list[dict]:
    """
    Run every active correlation rule against *log_dict* (the just-ingested
    log payload) and return a list of correlation results for each rule that
    fired.  Deduplicates against existing open [CORR] incidents within
    a 30-minute window to avoid duplicate alerts.

    Each result dict contains:
        rule_name, description, severity, matched_log_ids, group_key,
        evidence_summary
    """
    results: list[dict] = []

    for rule in CORRELATION_RULES:
        try:
            result = _evaluate_single_rule(db, rule, log_dict)
            if result is None:
                continue

            # ── Dedup: skip if an open [CORR] incident already exists ──
            title_prefix = f"[CORR] {result['rule_name']} - {result['group_key']}"
            dedup_cutoff = datetime.utcnow() - timedelta(minutes=_CORR_DEDUP_MINUTES)
            existing = (
                db.query(Incident)
                .filter(
                    Incident.title == title_prefix,
                    Incident.status == StatusEnum.open,
                    Incident.created_at >= dedup_cutoff,
                )
                .first()
            )
            if existing:
                logger.debug(
                    "Correlation '%s' suppressed — open incident #%d exists",
                    result["rule_name"], existing.id,
                )
                continue

            results.append(result)
        except Exception:
            logger.exception(
                "Error evaluating correlation rule '%s'", rule.name
            )

    if results:
        logger.info(
            "Correlation engine produced %d match(es) for event_type='%s'",
            len(results),
            log_dict.get("event_type"),
        )

    return results


def create_correlated_incident(db: Session, correlation_result: dict) -> Incident:
    """
    Persist an Incident derived from a correlation match.

    Title format:  [CORR] Rule Name - group_key
    The incident is linked to the first matched log as its trigger.
    """
    matched_ids: list[int] = correlation_result["matched_log_ids"]
    trigger_log_id = matched_ids[0] if matched_ids else None

    # Resolve the asset from the trigger log when available.
    asset_id: Optional[int] = None
    if trigger_log_id:
        trigger_log = db.query(Log).get(trigger_log_id)
        if trigger_log:
            asset_id = trigger_log.asset_id

    description_text = (
        f"{correlation_result['description']}\n\n"
        f"--- Evidence ---\n"
        f"{correlation_result['evidence_summary']}\n\n"
        f"Matched logs: {len(matched_ids)}"
    )

    incident = Incident(
        title=f"[CORR] {correlation_result['rule_name']} - {correlation_result['group_key']}",
        description=description_text,
        severity=correlation_result["severity"],
        status=StatusEnum.open,
        risk_score=_severity_to_risk(correlation_result["severity"]),
        ai_recommendation="Correlation-based incident — review matched logs for full context.",
        ioc_matches=[],
        affected_assets=[],
        trigger_log_id=trigger_log_id,
        asset_id=asset_id,
    )
    db.add(incident)
    db.flush()

    logger.info(
        "Created correlated incident #%d: %s",
        incident.id,
        incident.title,
    )

    return incident


# ── Helpers ───────────────────────────────────────────────────────────────────

def _severity_to_risk(severity: SeverityEnum) -> float:
    """Map a SeverityEnum to a representative risk score."""
    return {
        SeverityEnum.critical: 95.0,
        SeverityEnum.high:     80.0,
        SeverityEnum.medium:   60.0,
        SeverityEnum.low:      35.0,
        SeverityEnum.info:     10.0,
    }.get(severity, 50.0)
