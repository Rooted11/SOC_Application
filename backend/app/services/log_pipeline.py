from __future__ import annotations

from datetime import datetime
from typing import Optional

from .anomaly_detection import detector
from .claude_service import generate_incident_recommendation
from .database import Asset, Incident, Log, SessionLocal, SeverityEnum, StatusEnum
from .playbook import executor
from .threat_intel import threat_intel
from . import event_bus, config
from . import detection_rules


def process_log(db, log_dict: dict) -> dict:
    """
    Core log processing pipeline:
    - score anomaly
    - correlate IOC
    - persist log
    - create incident if needed
    - trigger playbook
    Returns the same shape as the legacy /ingest response.
    """
    entry_ts = log_dict.get("timestamp") or datetime.utcnow()

    # -- Anomaly scoring ------------------------------------------------------
    score_result = detector.score_log({**log_dict, "timestamp": entry_ts})

    # -- Rule-based detections -----------------------------------------------
    rule_matches, suppressed = detection_rules.evaluate_rules(db, log_dict)
    if rule_matches and not suppressed:
        score_result["is_anomalous"] = True
        score_result["risk_score"] = max(score_result["risk_score"], 70.0)

    # -- Asset linkage --------------------------------------------------------
    asset: Optional[Asset] = None
    ip_src = log_dict.get("ip_src")
    if ip_src:
        asset = db.query(Asset).filter(Asset.ip_address == ip_src).first()

    # -- Persist log ----------------------------------------------------------
    db_log = Log(
        source        = log_dict.get("source"),
        timestamp     = entry_ts,
        log_level     = log_dict.get("log_level", "info"),
        message       = log_dict.get("message"),
        raw_data      = log_dict.get("raw_data") or {},
        ip_src        = log_dict.get("ip_src"),
        ip_dst        = log_dict.get("ip_dst"),
        user          = log_dict.get("user"),
        event_type    = log_dict.get("event_type") or "unknown",
        anomaly_score = score_result["anomaly_score"],
        risk_score    = score_result["risk_score"],
        is_anomalous  = score_result["is_anomalous"],
        explanation   = score_result["explanation"],
        asset_id      = asset.id if asset else None,
    )
    db.add(db_log)
    db.flush()

    # -- IOC correlation ------------------------------------------------------
    ioc_matches = threat_intel.correlate_log(db, log_dict)

    # -- Incident creation ----------------------------------------------------
    incident_id = None
    if score_result["is_anomalous"] or ioc_matches:
        sev = detector.classify_severity(score_result["risk_score"])

        rec = generate_incident_recommendation(
            incident_title  = f"Anomaly: {log_dict.get('event_type')} from {log_dict.get('ip_src')}",
            severity        = sev,
            risk_score      = score_result["risk_score"],
            ioc_matches     = ioc_matches,
            explanation     = score_result["explanation"],
            event_type      = log_dict.get("event_type") or "",
            affected_assets = [asset.hostname] if asset else [],
        )

        incident = Incident(
            title             = f"[AUTO] {log_dict.get('event_type')} - {log_dict.get('ip_src') or 'unknown'} -> {log_dict.get('ip_dst') or 'unknown'}",
            description       = score_result["explanation"],
            severity          = SeverityEnum(sev),
            status            = StatusEnum.open,
            risk_score        = score_result["risk_score"],
            ai_recommendation = rec,
            ioc_matches       = [m["value"] for m in ioc_matches],
            affected_assets   = [asset.hostname] if asset else [],
            trigger_log_id    = db_log.id,
            asset_id          = asset.id if asset else None,
        )
        db.add(incident)
        db.flush()
        db_log.incident = incident
        db.commit()
        incident_id = incident.id

        executor.execute_for_incident(db, incident)

        if config.settings.use_redis_streams:
            event_bus.publish_event({
                "type": "incident_created",
                "incident_id": incident.id,
                "log_id": db_log.id,
                "severity": incident.severity.value,
                "risk_score": incident.risk_score,
                "is_anomalous": score_result["is_anomalous"],
            })
    else:
        db.commit()

    if config.settings.use_redis_streams:
        event_bus.publish_event({
            "type": "log_processed",
            "log_id": db_log.id,
            "incident_id": incident_id,
            "is_anomalous": score_result["is_anomalous"],
            "risk_score": score_result["risk_score"],
        })

    return {
        "log_id":       db_log.id,
        "is_anomalous": score_result["is_anomalous"],
        "risk_score":   score_result["risk_score"],
        "explanation":  score_result["explanation"],
        "ioc_matches":  len(ioc_matches),
        "incident_id":  incident_id,
    }


def process_log_payload(log_dict: dict) -> dict:
    """Convenience helper that opens/closes DB for standalone worker usage."""
    db = SessionLocal()
    try:
        return process_log(db, log_dict)
    finally:
        db.close()
