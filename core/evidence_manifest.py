"""
core/evidence_manifest.py — Evidence Manifest & Integrity Engine (Phase 1D)

Creates ONE immutable manifest per evidence item immediately after
hashing (Phase 1A) and digital signing (Phase 1C) both succeed.
Never re-creates an existing manifest (manifest_exists() guard).

Public API
----------
create_manifest(evidence_id, case_id=None)   → dict | None
load_manifest(evidence_id)                   → dict | None
verify_manifest(evidence_id)                 → "VALID" | "INVALID" | "MISSING"
export_manifest(evidence_id, fmt, out_path)  → str  (path written)
manifest_exists(evidence_id)                 → bool

Verification compares the three independent values stored at
acquisition time:
  • sha256_hash   vs current Evidence.sha256_hash
  • signature     vs current EvidenceSignature.signature
  • file_size     vs current Evidence.file_size

Any mismatch → "INVALID"; manifest row status updated accordingly.

Logging format
--------------
[EVIDENCE_MANIFEST]
Evidence ID: <int>
Manifest ID: <uuid>
Status: VALID | INVALID | MISSING | CREATED
Timestamp: <ISO8601 UTC>

Thread-safety: every public function opens its own DbSession,
commits, and closes before returning — no shared mutable state.
"""

import csv
import logging
import mimetypes
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("EvidenceManifest")

MANIFEST_VERSION = 1
_EXPORTS_DIR = "exports/manifests"

# ── Internal helpers ─────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _detect_mime(file_name: str, file_path: str) -> tuple[str, str]:
    """Return (mime_type, file_extension) from file name / path."""
    ext = os.path.splitext(file_name)[1].lower()
    if not ext and file_path:
        ext = os.path.splitext(file_path)[1].lower()
    mime, _ = mimetypes.guess_type(file_name)
    if not mime and file_path:
        mime, _ = mimetypes.guess_type(file_path)
    return (mime or "application/octet-stream", ext or "")


def _log(evidence_id: int, manifest_id: str, status: str, ts: datetime) -> None:
    logger.info(
        f"[EVIDENCE_MANIFEST]\n"
        f"Evidence ID: {evidence_id}\n"
        f"Manifest ID: {manifest_id}\n"
        f"Status: {status}\n"
        f"Timestamp: {ts.isoformat()}"
    )


# ── Core functions ───────────────────────────────────────────

def manifest_exists(evidence_id: int) -> bool:
    """Return True if a manifest row already exists for this evidence_id."""
    try:
        from database import DbSession, EvidenceManifest
        with DbSession() as s:
            return s.query(EvidenceManifest.manifest_id).filter(
                EvidenceManifest.evidence_id == evidence_id
            ).first() is not None
    except Exception as e:
        logger.error(f"manifest_exists({evidence_id}): {e}")
        return False


def create_manifest(
    evidence_id: int,
    case_id: Optional[str] = None,
    performed_by: str = "system",
) -> Optional[dict]:
    """
    Create an immutable manifest for evidence_id.

    Prerequisites (checked inside this function — returns None
    without raising if either is missing):
      • Evidence row with sha256_hash set
      • EvidenceSignature row with signature set

    Silently skips if a manifest already exists (one-per-evidence rule).
    Returns None on any DB or prerequisite failure — callers must never
    crash the broader pipeline over a manifest-creation failure.
    """
    if manifest_exists(evidence_id):
        logger.debug(f"Manifest already exists for evidence {evidence_id} — skipping")
        return load_manifest(evidence_id)

    try:
        from database import DbSession, Evidence, EvidenceSignature, EvidenceManifest
        with DbSession() as s:
            ev  = s.query(Evidence).filter(Evidence.id == evidence_id).first()
            sig = s.query(EvidenceSignature).filter(
                EvidenceSignature.evidence_id == evidence_id
            ).first()

            if ev is None:
                logger.error(f"create_manifest: Evidence {evidence_id} not found")
                return None
            if not ev.sha256_hash:
                logger.error(f"create_manifest: Evidence {evidence_id} has no sha256_hash")
                return None
            if sig is None:
                logger.error(
                    f"create_manifest: No signature for evidence {evidence_id} — "
                    f"sign first with core.evidence_signing.sign_hash()"
                )
                return None

            mime, ext = _detect_mime(ev.file_name, ev.file_path)
            mid  = str(uuid.uuid4())
            now  = _utcnow()

            row = EvidenceManifest(
                manifest_id             = mid,
                evidence_id             = evidence_id,
                case_id                 = str(case_id) if case_id is not None else None,
                sha256_hash             = ev.sha256_hash,
                signature               = sig.signature,
                signature_algorithm     = sig.algorithm,
                key_id                  = sig.key_id,
                public_key_fingerprint  = sig.public_key_fingerprint,
                file_name               = ev.file_name,
                file_size               = ev.file_size or 0,
                mime_type               = mime,
                file_extension          = ext,
                created_at              = now,
                acquired_at             = ev.created_at or now,
                manifest_version        = MANIFEST_VERSION,
                status                  = "VALID",
            )
            s.add(row)
            s.commit()
            result = row.to_json_safe()

        _log(evidence_id, mid, "CREATED", now)

        try:
            from core.chain_of_custody import record_event
            record_event(
                evidence_id=evidence_id,
                action="MANIFEST_CREATED",
                performed_by=performed_by,
                reason=f"Manifest {mid} created (v{MANIFEST_VERSION})",
                case_id=case_id,
            )
        except Exception:
            pass

        return result

    except Exception as e:
        logger.error(f"create_manifest({evidence_id}): {e}")
        return None


def load_manifest(evidence_id: int) -> Optional[dict]:
    """Return the manifest dict for evidence_id, or None if it does not exist."""
    try:
        from database import DbSession, EvidenceManifest
        with DbSession() as s:
            row = s.query(EvidenceManifest).filter(
                EvidenceManifest.evidence_id == evidence_id
            ).first()
            return row.to_json_safe() if row else None
    except Exception as e:
        logger.error(f"load_manifest({evidence_id}): {e}")
        return None


def verify_manifest(
    evidence_id: int,
    performed_by: str = "system",
) -> str:
    """
    Re-validate the manifest against the live Evidence and
    EvidenceSignature rows.

    Checks (ALL must match → VALID; any mismatch → INVALID):
      • manifest.sha256_hash  == evidence.sha256_hash
      • manifest.signature    == evidence_signature.signature
      • manifest.file_size    == evidence.file_size

    Updates manifest.status to "VALID" or "INVALID" in-place.
    Returns "VALID", "INVALID", or "MISSING".
    """
    now = _utcnow()
    mismatches: list = []
    mid = "n/a"
    result = "INVALID"
    try:
        from database import DbSession, Evidence, EvidenceSignature, EvidenceManifest
        with DbSession() as s:
            manifest = s.query(EvidenceManifest).filter(
                EvidenceManifest.evidence_id == evidence_id
            ).first()

            if manifest is None:
                _log(evidence_id, "n/a", "MISSING", now)
                return "MISSING"

            mid = manifest.manifest_id
            ev  = s.query(Evidence).filter(Evidence.id == evidence_id).first()
            sig = s.query(EvidenceSignature).filter(
                EvidenceSignature.evidence_id == evidence_id
            ).first()

            if ev is None:
                mismatches.append("evidence row missing")
            else:
                if (ev.sha256_hash or "") != manifest.sha256_hash:
                    mismatches.append(
                        f"sha256 changed: stored={manifest.sha256_hash[:16]}... "
                        f"current={str(ev.sha256_hash or '')[:16]}..."
                    )
                if (ev.file_size or 0) != manifest.file_size:
                    mismatches.append(
                        f"file_size changed: stored={manifest.file_size} "
                        f"current={ev.file_size}"
                    )
            if sig is None:
                mismatches.append("signature row missing")
            elif sig.signature != manifest.signature:
                mismatches.append("signature changed")

            result = "VALID" if not mismatches else "INVALID"
            manifest.status = result
            s.commit()

    except Exception as e:
        logger.error(f"verify_manifest({evidence_id}): {e}")
        return "INVALID"

    if mismatches:
        logger.warning(
            f"[EVIDENCE_MANIFEST]\n"
            f"Evidence ID: {evidence_id}\n"
            f"Manifest ID: {mid}\n"
            f"Status: INVALID — {'; '.join(mismatches)}\n"
            f"Timestamp: {now.isoformat()}"
        )
    else:
        _log(evidence_id, mid, result, now)

    try:
        from core.chain_of_custody import record_event
        record_event(
            evidence_id=evidence_id,
            action="MANIFEST_VERIFIED",
            performed_by=performed_by,
            reason=f"Manifest {mid}: {result}" + (f" — {'; '.join(mismatches)}" if mismatches else ""),
            status="OK" if result == "VALID" else "FAILED",
        )
    except Exception:
        pass

    return result


# ── Export ───────────────────────────────────────────────────

_CSV_FIELDS = [
    "manifest_id", "evidence_id", "case_id", "sha256_hash",
    "signature_algorithm", "key_id", "public_key_fingerprint",
    "file_name", "file_size", "mime_type", "file_extension",
    "created_at", "acquired_at", "manifest_version", "status",
]

_PDF_WIDTHS = [60, 190]   # mm, A4 portrait


def export_manifest(
    evidence_id: int,
    fmt: str = "json",
    out_path: Optional[str] = None,
) -> str:
    """
    Export the manifest for evidence_id to JSON, CSV, or PDF.
    Returns the written file path. Raises ValueError on bad format
    or RuntimeError if no manifest exists.
    """
    fmt = fmt.lower().strip()
    if fmt not in ("json", "csv", "pdf"):
        raise ValueError(f"Unsupported format '{fmt}'. Use json, csv, or pdf.")

    manifest = load_manifest(evidence_id)
    if manifest is None:
        raise RuntimeError(f"No manifest found for evidence {evidence_id}")

    os.makedirs(_EXPORTS_DIR, exist_ok=True)
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    if out_path is None:
        out_path = f"{_EXPORTS_DIR}/manifest_{evidence_id}_{ts_str}.{fmt}"

    if fmt == "json":
        _export_json(manifest, out_path)
    elif fmt == "csv":
        _export_csv(manifest, out_path)
    elif fmt == "pdf":
        _export_pdf(manifest, out_path)

    logger.info(f"[EVIDENCE_MANIFEST] Exported manifest for evidence {evidence_id} -> {out_path}")
    return out_path


def _export_json(manifest: dict, path: str) -> None:
    import json
    export = {k: v for k, v in manifest.items() if k != "signature"}
    export["export_generated_at"] = _utcnow().isoformat() + "Z"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2, ensure_ascii=False)


def _export_csv(manifest: dict, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[c for c in _CSV_FIELDS if c != "signature"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerow(manifest)


def _export_pdf(manifest: dict, path: str) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
        )
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        raise ImportError("reportlab required for PDF export. pip install reportlab")

    doc    = SimpleDocTemplate(path, pagesize=A4,
                                leftMargin=15*mm, rightMargin=15*mm,
                                topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    story  = [
        Paragraph("<b>Evidence Manifest</b>", styles["Heading1"]),
        Paragraph(
            f"Generated (UTC): {_utcnow().strftime('%Y-%m-%d %H:%M:%S')} &nbsp; "
            f"Version: {manifest.get('manifest_version', 1)}",
            styles["Normal"],
        ),
        Spacer(1, 6*mm),
    ]

    skip = {"signature", "id"}
    rows = [["Field", "Value"]]
    for field in _CSV_FIELDS:
        if field in skip:
            continue
        val = str(manifest.get(field, "") or "")
        if len(val) > 80:
            val = val[:77] + "..."
        rows.append([field, val])

    col_widths = [w * mm for w in _PDF_WIDTHS]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("FONTNAME",      (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",      (1, 1), (1, -1), "Helvetica"),
        ("GRID",          (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph(
        "<i>This manifest is an immutable forensic record. "
        "Any modification invalidates its integrity.</i>",
        styles["Normal"],
    ))
    doc.build(story)
