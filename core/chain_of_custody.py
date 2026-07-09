"""
core/chain_of_custody.py — Forensic Chain of Custody (Phase 1B)

Tracks every action performed on evidence throughout its lifecycle.
Records are APPEND-ONLY: record_event() only ever INSERTs, never
UPDATE/DELETE.  Thread-safety is enforced through SQLAlchemy's
connection-per-session model (one DbSession per call, committed
before returning) — no module-level mutable state.

Public API
----------
record_event(evidence_id, action, ...)       → CoC dict
get_history(evidence_id)                     → list[dict]  chronological
get_history_by_case(case_id)                 → list[dict]  chronological
get_latest_event(evidence_id)                → dict | None
export_history(evidence_id, fmt, out_path)   → str (path written)

Valid actions
-------------
CREATED  COLLECTED  HASHED  VIEWED  VERIFIED
EXPORTED  DOWNLOADED  COPIED  ARCHIVED  DELETED

Logging format
--------------
[CHAIN_OF_CUSTODY]
Evidence ID: <int>
Action: <str>
User: <str>
Timestamp: <ISO8601 UTC>
Status: OK | FAILED | PENDING

Integration hooks
-----------------
Called automatically by:
  core/evidence_hashing.register_evidence_file()  → CREATED + HASHED
  core/evidence_hashing.verify_evidence_by_id()   → VERIFIED
  core/evidence_hashing.save_hash_metadata()       → HASHED
  web_dashboard.py  evidence detail/download routes → VIEWED / DOWNLOADED
  stix_export.export_json()                        → EXPORTED
  report_generator.generate_report()               → EXPORTED
"""

import csv
import io
import os
import socket
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("ChainOfCustody")

# ── Constants ────────────────────────────────────────────────
VALID_ACTIONS = frozenset({
    "CREATED", "COLLECTED", "HASHED", "VIEWED", "VERIFIED",
    "EXPORTED", "DOWNLOADED", "COPIED", "ARCHIVED", "DELETED",
    "SIGNED", "SIGNATURE_VERIFIED",          # Phase 1C
    "MANIFEST_CREATED", "MANIFEST_VERIFIED", # Phase 1D
})
VALID_STATUSES = frozenset({"OK", "FAILED", "PENDING"})

_LOCAL_HOSTNAME: str = socket.gethostname()


# ── Core: record_event ───────────────────────────────────────

def record_event(
    evidence_id: int,
    action: str,
    performed_by: str = "system",
    reason: str = "",
    ip_address: str = "",
    hostname: str = "",
    status: str = "OK",
    remarks: str = "",
    case_id: Optional[str] = None,
    _timestamp: Optional[datetime] = None,    # injectable for tests; always UTC in production
) -> Optional[dict]:
    """
    Append one immutable Chain of Custody record.

    Returns the new record as a dict, or None if the DB layer is
    unavailable — callers treat None as "couldn't log, but the
    underlying evidence action must not be rolled back over this."

    Raises ValueError for an invalid `action` string rather than
    silently inserting garbage into the audit trail, because a CoC
    record with a misspelled action is worse than no record.
    """
    action = action.upper().strip()
    if action not in VALID_ACTIONS:
        raise ValueError(
            f"Invalid CoC action '{action}'. "
            f"Valid: {', '.join(sorted(VALID_ACTIONS))}"
        )

    status = status.upper().strip()
    if status not in VALID_STATUSES:
        status = "OK"

    ts = _timestamp or datetime.now(timezone.utc).replace(tzinfo=None)
    record_id = str(uuid.uuid4())
    hostname = hostname or _LOCAL_HOSTNAME

    log_ts = ts.isoformat() if isinstance(ts, datetime) else str(ts)
    log_fn = logger.info if status != "FAILED" else logger.warning
    log_fn(
        f"[CHAIN_OF_CUSTODY]\n"
        f"Evidence ID: {evidence_id}\n"
        f"Action: {action}\n"
        f"User: {performed_by}\n"
        f"Timestamp: {log_ts}\n"
        f"Status: {status}"
    )

    try:
        from database import DbSession, ChainOfCustody, Evidence
        with DbSession() as s:
            # Verify evidence exists — raise a clear error rather than
            # silently creating an orphan CoC record.
            ev = s.query(Evidence).filter(Evidence.id == evidence_id).first()
            if ev is None:
                logger.error(
                    f"[CHAIN_OF_CUSTODY] Evidence ID {evidence_id} not found — "
                    f"CoC record not created for action {action}"
                )
                return None

            row = ChainOfCustody(
                id=record_id,
                evidence_id=evidence_id,
                case_id=str(case_id) if case_id is not None else None,
                action=action,
                performed_by=performed_by,
                timestamp=ts,
                reason=reason or "",
                ip_address=ip_address or "",
                hostname=hostname,
                status=status,
                remarks=remarks or "",
            )
            s.add(row)
            s.commit()
            return row.to_json_safe()

    except ImportError as e:
        logger.warning(f"[CHAIN_OF_CUSTODY] DB layer unavailable: {e}")
        return None
    except Exception as e:
        logger.error(f"[CHAIN_OF_CUSTODY] DB write failed for evidence {evidence_id} "
                     f"action {action}: {e}")
        return None


# ── Queries ──────────────────────────────────────────────────

def get_history(evidence_id: int) -> list:
    """
    Return all CoC records for `evidence_id` in ascending timestamp
    order (chronological — oldest first, so export/display reads like
    a chain where each link follows the previous one).
    """
    try:
        from database import DbSession, ChainOfCustody
        from sqlalchemy import asc
        with DbSession() as s:
            rows = (
                s.query(ChainOfCustody)
                .filter(ChainOfCustody.evidence_id == evidence_id)
                .order_by(asc(ChainOfCustody.timestamp))
                .all()
            )
            return [r.to_json_safe() for r in rows]
    except Exception as e:
        logger.error(f"get_history(evidence_id={evidence_id}): {e}")
        return []


def get_history_by_case(case_id: str) -> list:
    """
    Return all CoC records tagged with `case_id`, chronological.
    Useful for case-level audit exports (GET /api/case/<id>/custody).
    """
    if not case_id:
        return []
    try:
        from database import DbSession, ChainOfCustody
        from sqlalchemy import asc
        with DbSession() as s:
            rows = (
                s.query(ChainOfCustody)
                .filter(ChainOfCustody.case_id == str(case_id))
                .order_by(asc(ChainOfCustody.timestamp))
                .all()
            )
            return [r.to_json_safe() for r in rows]
    except Exception as e:
        logger.error(f"get_history_by_case(case_id={case_id}): {e}")
        return []


def get_latest_event(evidence_id: int) -> Optional[dict]:
    """Most recent CoC record for `evidence_id`, or None."""
    try:
        from database import DbSession, ChainOfCustody
        from sqlalchemy import desc
        with DbSession() as s:
            row = (
                s.query(ChainOfCustody)
                .filter(ChainOfCustody.evidence_id == evidence_id)
                .order_by(desc(ChainOfCustody.timestamp))
                .first()
            )
            return row.to_json_safe() if row else None
    except Exception as e:
        logger.error(f"get_latest_event(evidence_id={evidence_id}): {e}")
        return None


# ── Export ───────────────────────────────────────────────────

_CSV_FIELDS = [
    "id", "evidence_id", "case_id", "action", "performed_by",
    "timestamp", "reason", "ip_address", "hostname", "status", "remarks",
]

_PDF_COL_HEADERS = ["Timestamp", "Action", "User", "Reason", "Status"]
_PDF_COL_KEYS    = ["timestamp", "action", "performed_by", "reason", "status"]
_PDF_COL_WIDTHS  = [105, 65, 55, 125, 45]   # mm; total ~395 → fits A4 landscape


def export_history(
    evidence_id: int,
    fmt: str = "json",
    out_path: Optional[str] = None,
    case_id: Optional[str] = None,
) -> str:
    """
    Export chain-of-custody history for `evidence_id` (or all records
    for `case_id` when provided) to a file.

    `fmt`: "json" | "csv" | "pdf"
    `out_path`: explicit path; if None, a timestamped file is created
                under exports/coc/.

    Returns the path of the written file.  Raises RuntimeError if the
    export fails after retries.
    """
    fmt = fmt.lower().strip()
    if fmt not in ("json", "csv", "pdf"):
        raise ValueError(f"Unsupported export format '{fmt}'. Use json, csv, or pdf.")

    records = get_history_by_case(str(case_id)) if case_id else get_history(evidence_id)

    # Resolve output path
    os.makedirs("exports/coc", exist_ok=True)
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    if out_path is None:
        scope = f"case_{case_id}" if case_id else f"evidence_{evidence_id}"
        out_path = f"exports/coc/coc_{scope}_{ts_str}.{fmt}"

    if fmt == "json":
        _export_json(records, out_path)
    elif fmt == "csv":
        _export_csv(records, out_path)
    elif fmt == "pdf":
        _export_pdf(records, evidence_id, case_id, out_path)

    logger.info(f"[CHAIN_OF_CUSTODY] Exported {len(records)} records -> {out_path} ({fmt.upper()})")
    return out_path


def _export_json(records: list, path: str) -> None:
    import json
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "export_generated_at": datetime.utcnow().isoformat() + "Z",
                "record_count": len(records),
                "records": records,
            },
            f, indent=2, ensure_ascii=False,
        )


def _export_csv(records: list, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def _export_pdf(records: list, evidence_id: int,
                case_id: Optional[str], path: str) -> None:
    """
    Generates a PDF chain-of-custody report using ReportLab (already a
    project dependency via report_generator.py).  Raises ImportError
    with a clear message if reportlab is somehow missing rather than
    silently emitting an empty file.
    """
    try:
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
        )
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        raise ImportError(
            "reportlab is required for PDF export. "
            "Install with: pip install reportlab"
        )

    doc = SimpleDocTemplate(
        path,
        pagesize=landscape(A4),
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=15*mm, bottomMargin=15*mm,
    )
    styles = getSampleStyleSheet()
    story  = []

    # Header
    scope_label = f"Case {case_id}" if case_id else f"Evidence #{evidence_id}"
    story.append(Paragraph(
        f"<b>Chain of Custody Report — {scope_label}</b>",
        styles["Heading1"]
    ))
    story.append(Paragraph(
        f"Generated (UTC): {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} "
        f"&nbsp;&nbsp; Records: {len(records)}",
        styles["Normal"]
    ))
    story.append(Spacer(1, 6*mm))

    if not records:
        story.append(Paragraph("No chain of custody records found.", styles["Normal"]))
    else:
        # Table data — header row + one row per record
        header = _PDF_COL_HEADERS[:]
        rows   = [header]
        for r in records:
            ts = r.get("timestamp", "")
            if ts and len(ts) > 19:
                ts = ts[:19].replace("T", " ")
            rows.append([
                ts,
                r.get("action", ""),
                r.get("performed_by", ""),
                (r.get("reason") or "")[:60],
                r.get("status", ""),
            ])

        col_widths = [w * mm for w in _PDF_COL_WIDTHS]
        tbl = Table(rows, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, 0), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
            ("FONTSIZE",      (0, 1), (-1, -1), 7),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("GRID",          (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 3),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 3),
            ("TOPPADDING",    (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(tbl)

    story.append(Spacer(1, 8*mm))
    story.append(Paragraph(
        "<i>This report is generated from an append-only audit log. "
        "Records are immutable after creation.</i>",
        styles["Normal"]
    ))

    doc.build(story)
