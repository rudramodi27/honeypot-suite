"""
stix_export.py — STIX 2.1 Threat Intelligence Export
Converts honeypot data into STIX 2.1 bundles for sharing with
CERTs, ISACs, government agencies, and security platforms.

Standards: STIX 2.1 (RFC-compliant), TAXII 2.1 compatible
TLP levels: WHITE | GREEN | AMBER | RED

Usage:
    from stix_export import StixExporter
    exporter = StixExporter()
    bundle = exporter.build_bundle(events, alerts)
    exporter.export_json(bundle, "threat_report.stix.json")
"""

import json
import uuid
import os
from datetime import datetime, timezone
from typing import Optional
import logging

logger = logging.getLogger("StixExporter")

try:
    from config_loader import cfg
    _IDENTITY_NAME  = cfg.get("stix.identity_name", "Honeypot Suite")
    _IDENTITY_CLASS = cfg.get("stix.identity_class", "system")
    _TLP_LEVEL      = cfg.get("stix.tlp_level", "white").upper()
except Exception:
    _IDENTITY_NAME  = "Honeypot Suite"
    _IDENTITY_CLASS = "system"
    _TLP_LEVEL      = "WHITE"

os.makedirs("exports", exist_ok=True)


# ── TLP Marking Definitions ───────────────────────────────────
TLP_MARKINGS = {
    "WHITE": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "white"},
    },
    "GREEN": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--34098fce-860f-479c-ad6f-a74bdf91f7d2",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "green"},
    },
    "AMBER": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "amber"},
    },
    "RED": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "red"},
    },
}


def _stix_id(obj_type: str) -> str:
    """Generate a valid STIX 2.1 ID."""
    return f"{obj_type}--{uuid.uuid4()}"


def _stix_ts(dt: Optional[datetime] = None) -> str:
    """STIX-compliant timestamp (UTC, ISO 8601 with ms)."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class StixExporter:
    """
    Builds STIX 2.1 bundles from honeypot intelligence.

    Output includes:
      - Identity (the honeypot system)
      - Indicators (malicious IPs, URLs, hashes, patterns)
      - Observed Data (raw attack observations)
      - Threat Actors (inferred from behavior)
      - Attack Patterns (MITRE ATT&CK techniques)
      - Malware (captured samples)
      - Relationships (linking all objects)
      - Reports (summary bundles)
    """

    def __init__(self, tlp_level: str = _TLP_LEVEL):
        self.tlp_level  = tlp_level.upper()
        self.tlp_ref    = TLP_MARKINGS.get(self.tlp_level, TLP_MARKINGS["WHITE"])
        self.identity   = self._build_identity()

    def _marking_refs(self) -> list[str]:
        return [self.tlp_ref["id"]]

    def _build_identity(self) -> dict:
        return {
            "type":            "identity",
            "spec_version":    "2.1",
            "id":              _stix_id("identity"),
            "created":         _stix_ts(),
            "modified":        _stix_ts(),
            "name":            _IDENTITY_NAME,
            "identity_class":  _IDENTITY_CLASS,
            "description":     "Advanced Honeypot Suite — automated threat collection system",
            "object_marking_refs": self._marking_refs(),
        }

    # ── Object builders ───────────────────────────────────────

    def ip_indicator(self, ip: str, confidence: int = 75,
                     labels: list[str] = None,
                     description: str = "",
                     first_seen: datetime = None,
                     last_seen: datetime = None) -> dict:
        """Build a STIX Indicator for a malicious IP address."""
        now = _stix_ts()
        return {
            "type":           "indicator",
            "spec_version":   "2.1",
            "id":             _stix_id("indicator"),
            "created":        now,
            "modified":       now,
            "created_by_ref": self.identity["id"],
            "name":           f"Malicious IP: {ip}",
            "description":    description or f"IP {ip} observed attacking honeypot services",
            "indicator_types": labels or ["malicious-activity"],
            "pattern":        f"[ipv4-addr:value = '{ip}']",
            "pattern_type":   "stix",
            "pattern_version":"2.1",
            "valid_from":     _stix_ts(first_seen),
            "valid_until":    _stix_ts(last_seen),
            "confidence":     confidence,
            "labels":         labels or ["malicious-activity"],
            "object_marking_refs": self._marking_refs(),
            "granular_markings": [],
        }

    def file_indicator(self, sha256: str, md5: str = "", sha1: str = "",
                       filename: str = "", file_type: str = "",
                       description: str = "") -> dict:
        """Build a STIX Indicator for a malware file hash."""
        now = _stix_ts()
        hashes = {"SHA-256": sha256}
        if md5:
            hashes["MD5"] = md5
        if sha1:
            hashes["SHA-1"] = sha1
        pattern_parts = [f"file:hashes.'{k}' = '{v}'" for k, v in hashes.items()]
        pattern = "[" + " AND ".join(pattern_parts) + "]"
        return {
            "type":           "indicator",
            "spec_version":   "2.1",
            "id":             _stix_id("indicator"),
            "created":        now,
            "modified":       now,
            "created_by_ref": self.identity["id"],
            "name":           f"Malware: {filename or sha256[:16]}",
            "description":    description or f"Malware sample captured by honeypot — {file_type}",
            "indicator_types": ["malicious-activity", "file-hash-watchlist"],
            "pattern":        pattern,
            "pattern_type":   "stix",
            "pattern_version":"2.1",
            "valid_from":     _stix_ts(),
            "confidence":     90,
            "object_marking_refs": self._marking_refs(),
        }

    def url_indicator(self, url: str, description: str = "") -> dict:
        """Build a STIX Indicator for a malicious URL."""
        now = _stix_ts()
        return {
            "type":           "indicator",
            "spec_version":   "2.1",
            "id":             _stix_id("indicator"),
            "created":        now,
            "modified":       now,
            "created_by_ref": self.identity["id"],
            "name":           f"Malicious URL: {url[:60]}",
            "description":    description,
            "indicator_types": ["malicious-activity"],
            "pattern":        f"[url:value = '{url}']",
            "pattern_type":   "stix",
            "pattern_version":"2.1",
            "valid_from":     _stix_ts(),
            "confidence":     70,
            "object_marking_refs": self._marking_refs(),
        }

    def attack_pattern(self, technique_id: str, technique_name: str,
                       tactic: str, description: str = "") -> dict:
        """Map MITRE ATT&CK technique to STIX AttackPattern."""
        now = _stix_ts()
        return {
            "type":           "attack-pattern",
            "spec_version":   "2.1",
            "id":             _stix_id("attack-pattern"),
            "created":        now,
            "modified":       now,
            "created_by_ref": self.identity["id"],
            "name":           technique_name,
            "description":    description,
            "aliases":        [technique_id],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name":      tactic.lower().replace(" ", "-"),
                }
            ],
            "external_references": [
                {
                    "source_name":   "mitre-attack",
                    "external_id":   technique_id,
                    "url":           f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                }
            ],
            "object_marking_refs": self._marking_refs(),
        }

    def malware_object(self, name: str, file_type: str,
                       sha256: str, is_family: bool = False) -> dict:
        """Build a STIX Malware object."""
        now = _stix_ts()
        return {
            "type":           "malware",
            "spec_version":   "2.1",
            "id":             _stix_id("malware"),
            "created":        now,
            "modified":       now,
            "created_by_ref": self.identity["id"],
            "name":           name or f"Unknown-{sha256[:8]}",
            "description":    f"Malware sample ({file_type}) captured by honeypot",
            "malware_types":  ["trojan", "backdoor"],
            "is_family":      is_family,
            "architecture_execution_envs": ["linux", "windows"],
            "object_marking_refs": self._marking_refs(),
        }

    def observed_data(self, events: list[dict]) -> dict:
        """Wrap raw events as STIX ObservedData."""
        now = _stix_ts()
        # Build network traffic objects
        network_objects = {}
        for i, ev in enumerate(events[:100]):              # cap at 100
            network_objects[str(i)] = {
                "type":     "network-traffic",
                "src_ref":  str(len(events) + i),
                "dst_port": ev.get("dst_port", 0),
                "protocols": ["tcp"],
            }
            network_objects[str(len(events) + i)] = {
                "type":  "ipv4-addr",
                "value": ev.get("src_ip", "0.0.0.0"),
            }
        return {
            "type":             "observed-data",
            "spec_version":     "2.1",
            "id":               _stix_id("observed-data"),
            "created":          now,
            "modified":         now,
            "created_by_ref":   self.identity["id"],
            "first_observed":   _stix_ts(self._parse_ts(events[0].get("timestamp"))) if events else now,
            "last_observed":    _stix_ts(self._parse_ts(events[-1].get("timestamp"))) if events else now,
            "number_observed":  len(events),
            "object_refs":      list(network_objects.keys()),
            "object_marking_refs": self._marking_refs(),
        }

    def relationship(self, source_id: str, target_id: str,
                     rel_type: str = "indicates") -> dict:
        now = _stix_ts()
        return {
            "type":               "relationship",
            "spec_version":       "2.1",
            "id":                 _stix_id("relationship"),
            "created":            now,
            "modified":           now,
            "created_by_ref":     self.identity["id"],
            "relationship_type":  rel_type,
            "source_ref":         source_id,
            "target_ref":         target_id,
            "object_marking_refs": self._marking_refs(),
        }

    def report_object(self, title: str, object_refs: list[str],
                      description: str = "", published: datetime = None) -> dict:
        now = _stix_ts()
        return {
            "type":           "report",
            "spec_version":   "2.1",
            "id":             _stix_id("report"),
            "created":        now,
            "modified":       now,
            "created_by_ref": self.identity["id"],
            "name":           title,
            "description":    description,
            "published":      _stix_ts(published),
            "report_types":   ["threat-actor-activity", "attack-pattern", "indicators"],
            "object_refs":    object_refs,
            "object_marking_refs": self._marking_refs(),
        }

    # ── Bundle builder ────────────────────────────────────────

    def build_bundle(self, events: list[dict] = None,
                     alerts: list[dict] = None,
                     malware_samples: list[dict] = None,
                     mitre_events: list[dict] = None) -> dict:
        """
        Build a complete STIX 2.1 bundle from honeypot data.
        Returns the full bundle as a dict.
        """
        events          = events or []
        alerts          = alerts or []
        malware_samples = malware_samples or []
        mitre_events    = mitre_events or []

        objects = [self.identity, self.tlp_ref]
        all_ids = []

        # ── IP Indicators from events ─────────────────────────
        seen_ips: dict = {}
        for ev in events:
            ip = ev.get("src_ip", "")
            if not ip or ip in seen_ips:
                continue
            # Gather context
            hit_count = sum(1 for e in events if e.get("src_ip") == ip)
            labels = ["malicious-activity"]
            if ev.get("is_scanner"):
                labels.append("scanner")
            if ev.get("is_tor"):
                labels.append("anonymization")
            confidence = min(95, 40 + hit_count * 5)
            ind = self.ip_indicator(
                ip=ip,
                confidence=confidence,
                labels=labels,
                description=f"Attacked {hit_count} times. "
                            f"Country: {ev.get('country','?')}. "
                            f"Service: {ev.get('service','?')}",
            )
            objects.append(ind)
            all_ids.append(ind["id"])
            seen_ips[ip] = ind["id"]

        # ── MITRE ATT&CK Patterns ─────────────────────────────
        seen_techniques: dict = {}
        for me in mitre_events:
            tid = me.get("technique_id", "")
            if not tid or tid in seen_techniques:
                continue
            ap = self.attack_pattern(
                technique_id=tid,
                technique_name=me.get("technique", "Unknown"),
                tactic=me.get("tactic", "unknown"),
                description=me.get("description", ""),
            )
            objects.append(ap)
            all_ids.append(ap["id"])
            seen_techniques[tid] = ap["id"]

        # ── Relationships: IP → ATT&CK technique ─────────────
        for ev in events:
            ip = ev.get("src_ip")
            tid = ev.get("mitre_id")
            if ip in seen_ips and tid in seen_techniques:
                rel = self.relationship(seen_ips[ip], seen_techniques[tid], "uses")
                objects.append(rel)

        # ── Malware samples ───────────────────────────────────
        for sample in malware_samples:
            sha256 = sample.get("sha256", "")
            if not sha256:
                continue
            file_ind = self.file_indicator(
                sha256=sha256,
                md5=sample.get("md5", ""),
                sha1=sample.get("sha1", ""),
                filename=sample.get("original_name", ""),
                file_type=sample.get("file_type", ""),
                description=f"Severity: {sample.get('severity','?')}. "
                            f"Uploaded by {sample.get('src_ip','?')} via {sample.get('service','?')}",
            )
            objects.append(file_ind)
            all_ids.append(file_ind["id"])

            malware_obj = self.malware_object(
                name=sample.get("original_name", ""),
                file_type=sample.get("file_type", ""),
                sha256=sha256,
            )
            objects.append(malware_obj)
            all_ids.append(malware_obj["id"])
            rel = self.relationship(file_ind["id"], malware_obj["id"], "indicates")
            objects.append(rel)

        # ── Summary Report ────────────────────────────────────
        if all_ids:
            ts = datetime.now(timezone.utc)
            report = self.report_object(
                title=f"Honeypot Threat Intelligence — {ts.strftime('%Y-%m-%d')}",
                object_refs=[self.identity["id"]] + all_ids,
                description=(
                    f"Automated threat intelligence from honeypot deployment. "
                    f"Period: last 24h. "
                    f"Events: {len(events)}. "
                    f"Unique IPs: {len(seen_ips)}. "
                    f"MITRE techniques: {len(seen_techniques)}. "
                    f"Malware samples: {len(malware_samples)}."
                ),
                published=ts,
            )
            objects.append(report)

        return {
            "type":         "bundle",
            "id":           _stix_id("bundle"),
            "spec_version": "2.1",
            "objects":      objects,
        }

    # ── Export methods ────────────────────────────────────────

    def export_json(self, bundle: dict, output_path: str = None) -> str:
        """Export STIX bundle to JSON file."""
        if not output_path:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"exports/stix_bundle_{ts}.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, ensure_ascii=False)
        logger.info(f"STIX bundle exported: {output_path} "
                    f"({len(bundle['objects'])} objects)")

        # Phase 1A Evidence Hashing Framework — register the exported
        # bundle as forensic evidence (additive; never blocks export).
        try:
            from core.evidence_hashing import register_evidence_file
            ev = register_evidence_file(output_path, source_type="stix_export", source_id=bundle.get("id"))
            # Phase 1B Chain of Custody — EXPORTED event
            if ev and ev.get("id"):
                from core.chain_of_custody import record_event
                record_event(
                    evidence_id=ev["id"],
                    action="EXPORTED",
                    performed_by="system",
                    reason=f"STIX 2.1 bundle exported ({len(bundle.get('objects', []))} objects)",
                )
        except Exception:
            pass

        return output_path

    def export_for_taxii(self, bundle: dict) -> str:
        """Serialize bundle for TAXII 2.1 push (compact JSON)."""
        return json.dumps(bundle, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _parse_ts(ts_val) -> Optional[datetime]:
        if isinstance(ts_val, datetime):
            return ts_val
        if isinstance(ts_val, str):
            try:
                return datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            except Exception:
                return None
        return None

    # ── Convenience: export from DB directly ─────────────────

    def export_from_db(self, hours: int = 24,
                       output_path: str = None) -> str:
        """Pull from SQLite DB and export STIX bundle."""
        try:
            from database import recent_events, recent_alerts, top_mitre_techniques, DbSession, MalwareSample, MitreEvent
            from sqlalchemy import desc
            from datetime import timedelta
            events  = recent_events(limit=500)
            alerts  = recent_alerts(limit=200)
            with DbSession() as s:
                malware = [m.to_json_safe() for m in
                           s.query(MalwareSample).order_by(desc(MalwareSample.timestamp)).limit(100)]
                mitre   = [m.__dict__ for m in
                           s.query(MitreEvent).order_by(desc(MitreEvent.timestamp)).limit(500)
                           if hasattr(m, '__dict__')]
            bundle = self.build_bundle(events, alerts, malware, mitre)
            return self.export_json(bundle, output_path)
        except Exception as e:
            logger.error(f"DB export failed: {e}")
            raise


if __name__ == "__main__":
    # Demo export with fake data
    exporter = StixExporter(tlp_level="GREEN")
    demo_events = [
        {"src_ip": "45.33.32.156", "service": "SSH", "event_type": "BRUTE_FORCE",
         "mitre_id": "T1110.001", "country": "US", "is_scanner": True},
        {"src_ip": "192.168.1.1", "service": "HTTP", "event_type": "SQL_INJECTION",
         "mitre_id": "T1190", "country": "CN"},
    ]
    demo_mitre = [
        {"technique_id": "T1110.001", "technique": "Brute Force: Password Guessing",
         "tactic": "Initial Access", "description": ""},
        {"technique_id": "T1190", "technique": "Exploit Public-Facing Application",
         "tactic": "Initial Access", "description": ""},
    ]
    bundle = exporter.build_bundle(events=demo_events, mitre_events=demo_mitre)
    path = exporter.export_json(bundle)
    print(f"[OK] STIX bundle: {path} ({len(bundle['objects'])} objects)")
