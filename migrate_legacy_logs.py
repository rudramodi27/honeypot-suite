"""
migrate_legacy_logs.py — Legacy JSON Log → SQLite Migration

Backfills the pre-v2.0 JSON-line log files into the new database so
historical attack data isn't lost when upgrading an existing deployment.

Sources (all optional — skipped if missing):
  logs/honeypot_master.log   → AttackEvent
  logs/mitre_mappings.log    → MitreEvent
  alerts/alerts.log          → Alert

Idempotent: tracks the last processed byte offset per file in
`.migration_state.json`, so re-running only ingests lines appended
since the last run (safe to call from cron, or once after `docker-compose up`
the first time you point this at an existing data/ volume).

Usage:
    python migrate_legacy_logs.py
    python migrate_legacy_logs.py --reset      # ignore offsets, re-import everything
    python migrate_legacy_logs.py --dry-run     # parse and report counts, write nothing
"""

import argparse
import json
import os
import sys
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("LogMigrator")

STATE_FILE = ".migration_state.json"


def _load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def _iter_new_lines(path: str, state: dict, reset: bool):
    """Yield JSON-parsed lines appended since the last recorded offset."""
    if not os.path.exists(path):
        logger.info(f"  (skip — not found: {path})")
        return
    start_offset = 0 if reset else state.get(path, 0)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(start_offset)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                logger.warning(f"  skipping malformed line in {path}")
        state[path] = f.tell()


def _parse_ts(ts_val) -> datetime:
    if isinstance(ts_val, str):
        try:
            return datetime.fromisoformat(ts_val)
        except ValueError:
            pass
    return datetime.utcnow()


def migrate(dry_run: bool = False, reset: bool = False) -> dict:
    from database import init_db, DbSession, AttackEvent, Alert, MitreEvent

    if not dry_run:
        init_db()

    state = {} if reset else _load_state()
    counts = {"events": 0, "alerts": 0, "mitre": 0}

    # ── 1. AttackEvent ◄ logs/honeypot_master.log ──────────────
    logger.info("Migrating logs/honeypot_master.log -> attack_events ...")
    event_rows = []
    for entry in _iter_new_lines("logs/honeypot_master.log", state, reset):
        event_rows.append(dict(
            timestamp   = _parse_ts(entry.get("timestamp")),
            service     = entry.get("service", "UNKNOWN"),
            src_ip      = entry.get("ip", "0.0.0.0"),
            dst_port    = entry.get("port", 0),
            event_type  = entry.get("event", ""),
            username    = entry.get("username"),
            password    = entry.get("password"),
            command     = entry.get("command"),
            url_path    = entry.get("path"),
            user_agent  = entry.get("user_agent"),
            payload     = entry.get("payload"),
            severity    = "LOW",          # legacy logs predate severity classification
            country     = entry.get("country"),
            asn         = entry.get("asn"),
            session_id  = entry.get("session_id") or None,
            raw_log     = entry,
        ))
    counts["events"] = len(event_rows)
    if event_rows and not dry_run:
        with DbSession() as s:
            s.bulk_insert_mappings(AttackEvent, event_rows)
            s.commit()

    # ── 2. Alert ◄ alerts/alerts.log ────────────────────────────
    logger.info("Migrating alerts/alerts.log -> alerts ...")
    alert_rows = []
    for entry in _iter_new_lines("alerts/alerts.log", state, reset):
        alert_rows.append(dict(
            timestamp   = _parse_ts(entry.get("timestamp")),
            severity    = entry.get("severity", "MEDIUM"),
            alert_type  = entry.get("type", ""),
            src_ip      = entry.get("ip", "0.0.0.0"),
            service     = entry.get("service", ""),
            description = entry.get("detail", ""),
            details     = entry,
        ))
    counts["alerts"] = len(alert_rows)
    if alert_rows and not dry_run:
        with DbSession() as s:
            s.bulk_insert_mappings(Alert, alert_rows)
            s.commit()

    # ── 3. MitreEvent ◄ logs/mitre_mappings.log ─────────────────
    logger.info("Migrating logs/mitre_mappings.log -> mitre_events ...")
    mitre_rows = []
    for entry in _iter_new_lines("logs/mitre_mappings.log", state, reset):
        mitre_rows.append(dict(
            timestamp     = _parse_ts(entry.get("timestamp")),
            src_ip        = entry.get("ip", ""),
            service       = entry.get("service", ""),
            tactic        = entry.get("tactic", ""),
            tactic_id     = entry.get("tactic_id", ""),
            technique     = entry.get("technique", ""),
            technique_id  = entry.get("id", ""),
            confidence    = entry.get("confidence", ""),
            description   = entry.get("description", ""),
            raw_event     = entry,
        ))
    counts["mitre"] = len(mitre_rows)
    if mitre_rows and not dry_run:
        with DbSession() as s:
            s.bulk_insert_mappings(MitreEvent, mitre_rows)
            s.commit()

    if not dry_run:
        _save_state(state)

    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate legacy JSON logs into SQLite")
    parser.add_argument("--reset", action="store_true",
                        help="Ignore saved offsets, re-import everything from byte 0")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse and count only — write nothing to the DB or state file")
    args = parser.parse_args()

    counts = migrate(dry_run=args.dry_run, reset=args.reset)

    print()
    print("=" * 50)
    print(f"  {'DRY RUN — ' if args.dry_run else ''}Migration summary")
    print("=" * 50)
    print(f"  Attack events migrated: {counts['events']}")
    print(f"  Alerts migrated:        {counts['alerts']}")
    print(f"  MITRE mappings migrated:{counts['mitre']}")
    print("=" * 50)
    if args.dry_run:
        print("  (dry run — nothing was written)")
