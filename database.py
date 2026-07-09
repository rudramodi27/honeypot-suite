"""
database.py — SQLAlchemy Database Layer
Replaces JSON log files with a proper relational database.

Tables:
  - attack_events   : every connection / attempt
  - ip_intel        : enriched IP metadata (cached)
  - alerts          : generated alerts
  - sessions        : full session records
  - mitre_events    : MITRE ATT&CK mapped events
  - malware_samples : captured malware metadata

Usage:
    from database import DbSession, AttackEvent, init_db
    init_db()
    with DbSession() as s:
        s.add(AttackEvent(...))
        s.commit()
"""

import os
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    DateTime, Text, Boolean, JSON, Index,
    event as sa_event
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool
import logging

logger = logging.getLogger("HoneypotDB")

# ── Engine setup ──────────────────────────────────────────────
try:
    from config_loader import cfg
    DB_URL = cfg.get("database.url", "sqlite:///honeypot.db")
    ECHO   = cfg.get("database.echo", False)
except Exception:
    DB_URL = "sqlite:///honeypot.db"
    ECHO   = False

_engine_kwargs: dict = {}
if DB_URL.startswith("sqlite"):
    _engine_kwargs = {
        "connect_args": {"check_same_thread": False},
        "poolclass": StaticPool,
    }

engine = create_engine(DB_URL, echo=ECHO, **_engine_kwargs)

# Enable WAL mode for SQLite (much better concurrent read performance)
if DB_URL.startswith("sqlite"):
    @sa_event.listens_for(engine, "connect")
    def _set_wal(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA journal_mode=WAL")
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

DbSession = sessionmaker(bind=engine)
Base = declarative_base()


# ── Models ────────────────────────────────────────────────────

class AttackEvent(Base):
    """Every inbound connection / attack attempt."""
    __tablename__ = "attack_events"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    service     = Column(String(32), nullable=False, index=True)   # SSH | HTTP | FTP | REDIS …
    src_ip      = Column(String(45), nullable=False, index=True)   # IPv4 or IPv6
    src_port    = Column(Integer)
    dst_port    = Column(Integer)
    event_type  = Column(String(64), index=True)                   # LOGIN_ATTEMPT | SCAN | UPLOAD …
    username    = Column(String(256))
    password    = Column(String(256))
    command     = Column(Text)
    url_path    = Column(Text)
    user_agent  = Column(Text)
    payload     = Column(Text)
    severity    = Column(String(16), default="LOW", index=True)    # LOW | MEDIUM | HIGH | CRITICAL
    country     = Column(String(64))
    city        = Column(String(64))
    org         = Column(String(128))
    asn         = Column(String(32))
    is_tor      = Column(Boolean, default=False)
    is_vpn      = Column(Boolean, default=False)
    is_scanner  = Column(Boolean, default=False)
    mitre_id    = Column(String(32))                               # e.g. T1110.001
    session_id  = Column(String(64), index=True, nullable=True)
    # NOTE: intentionally NOT a ForeignKey to sessions.session_id.
    # session_recorder.py's full-session capture is a separate JSON-based
    # system not yet bridged into the `sessions` table below, so a hard FK
    # here would (and during testing, did) reject valid events — e.g. an
    # HTTP LOGIN_SUCCESS carrying a real session token with no
    # corresponding `sessions` row. Treat this as a soft/manual join key.
    raw_log     = Column(JSON)

    __table_args__ = (
        Index("ix_events_ip_time", "src_ip", "timestamp"),
        Index("ix_events_service_type", "service", "event_type"),
    )

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns
                if not isinstance(getattr(self, c.name), datetime)
                or (setattr(self, c.name, getattr(self, c.name)) or True)}

    def to_json_safe(self) -> dict:
        d = {}
        for c in self.__table__.columns:
            v = getattr(self, c.name)
            d[c.name] = v.isoformat() if isinstance(v, datetime) else v
        return d


class IPIntel(Base):
    """Cached IP intelligence (geo + threat data)."""
    __tablename__ = "ip_intel"

    ip              = Column(String(45), primary_key=True)
    last_seen       = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    country         = Column(String(64))
    country_code    = Column(String(4))
    city            = Column(String(64))
    region          = Column(String(64))
    latitude        = Column(Float)
    longitude       = Column(Float)
    org             = Column(String(128))
    asn             = Column(String(32))
    isp             = Column(String(128))
    is_tor          = Column(Boolean, default=False)
    is_vpn          = Column(Boolean, default=False)
    is_datacenter   = Column(Boolean, default=False)
    is_scanner      = Column(Boolean, default=False)
    abuse_score     = Column(Integer, default=0)          # 0-100 from AbuseIPDB
    threat_label    = Column(String(64))
    vt_malicious    = Column(Integer, default=0)          # VirusTotal positives
    total_hits      = Column(Integer, default=0)
    first_seen      = Column(DateTime, default=datetime.utcnow)
    raw_intel       = Column(JSON)


class Alert(Base):
    """Generated security alerts."""
    __tablename__ = "alerts"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    severity    = Column(String(16), nullable=False, index=True)
    alert_type  = Column(String(64), index=True)
    src_ip      = Column(String(45), index=True)
    service     = Column(String(32))
    description = Column(Text)
    mitre_id    = Column(String(32))
    mitre_name  = Column(String(128))
    notified    = Column(Boolean, default=False)
    acknowledged= Column(Boolean, default=False)
    ack_by      = Column(String(64))
    ack_time    = Column(DateTime)
    details     = Column(JSON)

    def to_json_safe(self) -> dict:
        d = {}
        for c in self.__table__.columns:
            v = getattr(self, c.name)
            d[c.name] = v.isoformat() if isinstance(v, datetime) else v
        return d


class AttackSession(Base):
    """Full attacker session records (SSH/FTP shell sessions, HTTP logins)."""
    __tablename__ = "sessions"

    session_id      = Column(String(64), primary_key=True)
    start_time      = Column(DateTime, default=datetime.utcnow, index=True)
    end_time        = Column(DateTime)
    duration_secs   = Column(Float)
    service         = Column(String(32), index=True)
    src_ip          = Column(String(45), index=True)
    src_port        = Column(Integer)
    username        = Column(String(256))
    password        = Column(String(256))
    commands        = Column(JSON)                       # list of commands
    files_accessed  = Column(JSON)
    uploads         = Column(JSON)
    typing_speed_wpm= Column(Float)
    is_automated    = Column(Boolean, default=True)
    keystroke_data  = Column(JSON)
    country         = Column(String(64))
    asn             = Column(String(32))

    # No ORM relationship to AttackEvent — see note on AttackEvent.session_id
    # above. Correlate the two tables with a manual query on session_id
    # when needed (e.g. `WHERE attack_events.session_id = sessions.session_id`).

    def to_json_safe(self) -> dict:
        d = {}
        for c in self.__table__.columns:
            v = getattr(self, c.name)
            d[c.name] = v.isoformat() if isinstance(v, datetime) else v
        return d


class MitreEvent(Base):
    """MITRE ATT&CK mapped detections."""
    __tablename__ = "mitre_events"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    timestamp       = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip          = Column(String(45), index=True)
    service         = Column(String(32))
    tactic          = Column(String(64), index=True)
    tactic_id       = Column(String(16))
    technique       = Column(String(128))
    technique_id    = Column(String(16), index=True)
    sub_technique   = Column(String(128))
    confidence      = Column(String(16))
    description     = Column(Text)
    raw_event       = Column(JSON)

    __table_args__ = (
        Index("ix_mitre_tactic_tech", "tactic_id", "technique_id"),
    )


class MalwareSample(Base):
    """Captured malware file metadata."""
    __tablename__ = "malware_samples"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    timestamp       = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip          = Column(String(45))
    service         = Column(String(32))
    original_name   = Column(String(256))
    saved_path      = Column(String(512))
    file_size       = Column(Integer)
    md5             = Column(String(32), index=True)
    sha1            = Column(String(40))
    sha256          = Column(String(64), index=True)
    sha512          = Column(String(128))
    file_type       = Column(String(64))
    extension       = Column(String(16))
    severity        = Column(String(16))
    yara_matches    = Column(JSON)
    webshell_matches= Column(JSON)
    vt_report       = Column(JSON)
    is_quarantined  = Column(Boolean, default=True)
    notes           = Column(Text)


class Evidence(Base):
    """
    Forensic evidence file registry — Phase 1A Evidence Hashing
    Framework. Tracks ANY file the honeypot suite treats as evidence:
    captured malware samples, generated PDF/STIX/JSON exports, saved
    session recordings, etc. Hashing itself is performed by
    core/evidence_hashing.py; this table is just the system-of-record
    for the results.

    `source_type`/`source_id` are a soft, manual-join reference back to
    the originating row (e.g. source_type="malware_sample",
    source_id=<malware_samples.id>) rather than a hard ForeignKey —
    evidence can originate from several different tables
    (malware_samples, sessions, ad-hoc report exports with no DB row at
    all), and a single FK target doesn't fit that. See the FK-removal
    note on AttackEvent.session_id above for why this codebase
    deliberately avoids hard FKs across loosely-related tables.
    """
    __tablename__ = "evidence"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    file_name       = Column(String(256), nullable=False)
    file_path       = Column(String(512), nullable=False, unique=True)
    file_size       = Column(Integer)
    source_type     = Column(String(32), index=True)   # malware_sample | report_export | stix_export | session_recording | manual
    source_id       = Column(String(64), index=True, nullable=True)

    sha256_hash     = Column(String(64), index=True)   # mandatory
    sha1_hash       = Column(String(40), nullable=True)   # optional
    md5_hash        = Column(String(32), nullable=True)   # optional

    hash_created_at = Column(DateTime, default=datetime.utcnow)
    hash_verified   = Column(Boolean, default=False)
    last_verified_at= Column(DateTime, nullable=True)
    verification_count = Column(Integer, default=0)

    created_at      = Column(DateTime, default=datetime.utcnow, index=True)
    notes           = Column(Text)

    def to_json_safe(self) -> dict:
        d = {}
        for c in self.__table__.columns:
            v = getattr(self, c.name)
            d[c.name] = v.isoformat() if isinstance(v, datetime) else v
        return d


class EvidenceSignature(Base):
    """
    Cryptographic signature for evidence SHA-256 hashes — Phase 1C.

    One row per evidence_id (the most recent signature overwrites the
    previous one on re-signing; signature history is preserved via the
    ChainOfCustody SIGNED events, not this table).

    Stores only the signature and its metadata — private key material
    is NEVER stored here or anywhere in the database.
    """
    __tablename__ = "evidence_signatures"

    id                      = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id             = Column(Integer, nullable=False, unique=True, index=True)
    signature               = Column(Text, nullable=False)       # hex-encoded bytes
    algorithm               = Column(String(16), nullable=False) # ed25519 | rsa4096
    key_id                  = Column(String(32), nullable=False) # hex(urandom(8))
    public_key_fingerprint  = Column(String(95), nullable=False) # SHA-256 of DER public key
    signed_sha256           = Column(String(64), nullable=False) # the hash that was signed
    signed_at               = Column(DateTime, nullable=False, index=True)

    def to_json_safe(self) -> dict:
        d = {}
        for c in self.__table__.columns:
            v = getattr(self, c.name)
            d[c.name] = v.isoformat() if isinstance(v, datetime) else v
        return d


class EvidenceManifest(Base):
    """
    Immutable Evidence Manifest — Phase 1D.

    Created ONCE per evidence item after hashing AND signing both
    succeed. Never updated or deleted — represents the trusted
    forensic metadata snapshot at acquisition time.

    manifest_id: UUID4 string (hex form, no dashes stripped)
    status:      VALID | INVALID | PENDING
                 Set to VALID at creation; set to INVALID if
                 verify_manifest() detects a mismatch.
    manifest_version: schema version integer, incremented here if
                      the model ever evolves (currently 1).
    """
    __tablename__ = "evidence_manifests"

    manifest_id             = Column(String(36), primary_key=True)
    evidence_id             = Column(Integer, nullable=False, unique=True, index=True)
    case_id                 = Column(String(64), nullable=True, index=True)

    sha256_hash             = Column(String(64), nullable=False)
    signature               = Column(Text, nullable=False)
    signature_algorithm     = Column(String(16), nullable=False)
    key_id                  = Column(String(32), nullable=False)
    public_key_fingerprint  = Column(String(95), nullable=False)

    file_name               = Column(String(256), nullable=False)
    file_size               = Column(Integer, nullable=False)
    mime_type                = Column(String(128), nullable=False, default="application/octet-stream")
    file_extension           = Column(String(32), nullable=False, default="")

    created_at               = Column(DateTime, nullable=False, index=True)
    acquired_at               = Column(DateTime, nullable=False)
    manifest_version          = Column(Integer, nullable=False, default=1)
    status                    = Column(String(16), nullable=False, default="VALID", index=True)

    def to_json_safe(self) -> dict:
        d = {}
        for c in self.__table__.columns:
            v = getattr(self, c.name)
            d[c.name] = v.isoformat() if isinstance(v, datetime) else v
        return d


class ChainOfCustody(Base):
    """
    Forensic Chain of Custody — Phase 1B.

    APPEND-ONLY: no UPDATE or DELETE is ever issued against this table
    by application code.  For SQLite the journal_mode=WAL pragma
    (already set in this file) makes concurrent reads safe.  For
    PostgreSQL production deployments, revoke UPDATE/DELETE from the
    application role at the DB layer (see hardening/vault_commands.sh
    for the pattern).

    `case_id` is a nullable soft-reference: this codebase deliberately
    avoids hard ForeignKeys across loosely-related tables (see the note
    on AttackEvent.session_id).  Pass None when recording an event that
    is not yet associated with a case; callers can update the UI filter
    or case-assignment logic without touching this immutable record.

    `id` is a UUID string (str(uuid.uuid4())) rather than an auto-
    increment integer so records can be generated offline and merged
    without collision — useful when the honeypot writes CoC entries
    to a local buffer before the DB connection is restored.
    """
    __tablename__ = "chain_of_custody"

    id           = Column(String(36), primary_key=True)   # UUID4 string
    evidence_id  = Column(Integer, nullable=False, index=True)
    case_id      = Column(String(64), nullable=True, index=True)

    action       = Column(String(32), nullable=False, index=True)
    # Valid values (enforced in core/chain_of_custody.py, not at DB level
    # so the constraint doesn't cause migration pain if new actions are
    # added later): CREATED COLLECTED HASHED VIEWED VERIFIED EXPORTED
    #               DOWNLOADED COPIED ARCHIVED DELETED

    performed_by = Column(String(128), nullable=False)
    timestamp    = Column(DateTime, nullable=False, index=True)
    reason       = Column(Text)
    ip_address   = Column(String(45))
    hostname     = Column(String(255))
    status       = Column(String(16), nullable=False, default="OK")
    # OK | FAILED | PENDING
    remarks      = Column(Text)

    __table_args__ = (
        Index("ix_coc_evidence_ts", "evidence_id", "timestamp"),
        Index("ix_coc_case_ts",     "case_id",     "timestamp"),
    )

    def to_json_safe(self) -> dict:
        d = {}
        for c in self.__table__.columns:
            v = getattr(self, c.name)
            d[c.name] = v.isoformat() if isinstance(v, datetime) else v
        return d

def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(engine)
    logger.info(f"Database initialized: {DB_URL}")


def get_session():
    """Context-manager-ready session factory."""
    return DbSession()


def bulk_insert_events(events: list[dict]):
    """Fast bulk insert for high-volume logging."""
    with DbSession() as s:
        s.bulk_insert_mappings(AttackEvent, events)
        s.commit()


# ── Statistics queries ────────────────────────────────────────
from sqlalchemy import func, desc

def stats_last_n_hours(hours: int = 24) -> dict:
    """Quick stats for dashboard."""
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    with DbSession() as s:
        total  = s.query(func.count(AttackEvent.id)).filter(AttackEvent.timestamp >= cutoff).scalar()
        unique = s.query(func.count(func.distinct(AttackEvent.src_ip))).filter(AttackEvent.timestamp >= cutoff).scalar()
        by_svc = dict(s.query(AttackEvent.service, func.count(AttackEvent.id))
                       .filter(AttackEvent.timestamp >= cutoff)
                       .group_by(AttackEvent.service).all())
        by_sev = dict(s.query(AttackEvent.severity, func.count(AttackEvent.id))
                       .filter(AttackEvent.timestamp >= cutoff)
                       .group_by(AttackEvent.severity).all())
        top_ips = s.query(AttackEvent.src_ip, func.count(AttackEvent.id).label("cnt"))\
                   .filter(AttackEvent.timestamp >= cutoff)\
                   .group_by(AttackEvent.src_ip)\
                   .order_by(desc("cnt")).limit(10).all()
    return {
        "total_events":   total,
        "unique_ips":     unique,
        "by_service":     by_svc,
        "by_severity":    by_sev,
        "top_ips":        [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
    }


def recent_alerts(limit: int = 50) -> list[dict]:
    with DbSession() as s:
        rows = s.query(Alert).order_by(desc(Alert.timestamp)).limit(limit).all()
        return [r.to_json_safe() for r in rows]


def recent_events(limit: int = 100, service: str = None) -> list[dict]:
    with DbSession() as s:
        q = s.query(AttackEvent).order_by(desc(AttackEvent.timestamp))
        if service:
            q = q.filter(AttackEvent.service == service)
        rows = q.limit(limit).all()
        return [r.to_json_safe() for r in rows]


def top_mitre_techniques(limit: int = 10) -> list[dict]:
    with DbSession() as s:
        rows = s.query(
            MitreEvent.technique_id,
            MitreEvent.technique,
            MitreEvent.tactic,
            func.count(MitreEvent.id).label("count")
        ).group_by(MitreEvent.technique_id).order_by(desc("count")).limit(limit).all()
        return [{"id": r[0], "name": r[1], "tactic": r[2], "count": r[3]} for r in rows]


# Auto-init when imported as main module
if __name__ == "__main__":
    init_db()
    print("[OK] Database initialized")
