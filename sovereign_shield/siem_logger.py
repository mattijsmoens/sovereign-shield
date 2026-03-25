"""
SIEMLogger — Structured Security Event Logger for SovereignShield
==================================================================
Formats security events into structured JSON or CEF format compatible
with SIEM platforms (Splunk, Elastic, QRadar, Sentinel).

Zero external dependencies. Pure Python stdlib.
"""

import json
import logging
import os
import time
import threading

logger = logging.getLogger("sovereign_shield.siem")


class Severity:
    """CEF severity levels."""
    INFO = 1
    LOW = 3
    MEDIUM = 5
    HIGH = 7
    VERY_HIGH = 8
    CRITICAL = 10


_EVENT_SEVERITY = {
    "action_allowed": Severity.INFO,
    "rate_limited": Severity.LOW,
    "input_blocked": Severity.HIGH,
    "injection_detected": Severity.HIGH,
    "ethical_violation": Severity.MEDIUM,
    "code_exfiltration": Severity.VERY_HIGH,
    "integrity_violation": Severity.CRITICAL,
    "killswitch_activated": Severity.CRITICAL,
    "malware_syntax": Severity.VERY_HIGH,
    "privilege_violation": Severity.CRITICAL,
}


class SIEMLogger:
    """
    Structured security event logger for SIEM integration.

    Usage:
        siem = SIEMLogger(output_path="logs/security_events.log")
        siem.log_block("InputFilter", "SCAN", "Injection detected")
        siem.log_allow("API", "SCAN")
    """

    def __init__(self, output_path=os.path.join("logs", "siem_events.log"),
                 log_format="json", device_vendor="SovereignShield",
                 device_product="AI Firewall", device_version="2.0.0",
                 max_file_size_mb=50, format=None):
        self.output_path = output_path
        effective_format = format if format is not None else log_format
        self.log_format = effective_format.lower()
        self.device_vendor = device_vendor
        self.device_product = device_product
        self.device_version = device_version
        self.max_file_size_mb = max_file_size_mb
        self._lock = threading.Lock()

        log_dir = os.path.dirname(output_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

    def log_event(self, event_type, action_type="", payload_summary="",
                  source_component="", session_id="", user_id="",
                  reason="", severity=None, extra=None):
        """Log a security event. Returns the formatted event record."""
        if severity is None:
            severity = _EVENT_SEVERITY.get(event_type, Severity.MEDIUM)

        import datetime
        timestamp = datetime.datetime.now(
            datetime.timezone.utc
        ).astimezone().isoformat(timespec="seconds")
        epoch = time.time()

        event = {
            "timestamp": timestamp,
            "epoch": epoch,
            "event_type": event_type,
            "severity": severity,
            "severity_label": self._severity_label(severity),
            "source_component": source_component,
            "action_type": action_type,
            "payload_summary": payload_summary[:500],
            "session_id": session_id,
            "user_id": user_id,
            "reason": reason,
            "device_vendor": self.device_vendor,
            "device_product": self.device_product,
            "device_version": self.device_version,
        }
        if extra:
            event["extra"] = extra

        if self.log_format == "cef":
            line = self._to_cef(event)
        else:
            line = json.dumps(event, ensure_ascii=False)

        self._write_line(line)
        return event

    def log_block(self, source_component, action_type, reason, **kwargs):
        """Shortcut for logging a blocked action."""
        return self.log_event(
            event_type="input_blocked",
            source_component=source_component,
            action_type=action_type, reason=reason, **kwargs
        )

    def log_allow(self, source_component, action_type,
                  reason="Action authorized.", **kwargs):
        """Shortcut for logging an allowed action."""
        return self.log_event(
            event_type="action_allowed",
            source_component=source_component,
            action_type=action_type, reason=reason, **kwargs
        )

    def _to_cef(self, event):
        """Format event as CEF."""
        vendor = self._cef_escape(self.device_vendor)
        product = self._cef_escape(self.device_product)
        version = self._cef_escape(self.device_version)
        name = self._cef_escape(event.get("reason", event["event_type"])[:200])
        severity = event["severity"]
        extensions = []
        if event.get("action_type"):
            extensions.append(f"act={event['action_type']}")
        if event.get("source_component"):
            extensions.append(f"cs1={event['source_component']}")
            extensions.append("cs1Label=SourceComponent")
        if event.get("payload_summary"):
            extensions.append(f"msg={event['payload_summary'][:200]}")
        extensions.append(f"rt={int(event['epoch'] * 1000)}")
        ext_str = " ".join(extensions)
        return (
            f"CEF:0|{vendor}|{product}|{version}|"
            f"{event['event_type']}|{name}|{severity}|{ext_str}"
        )

    @staticmethod
    def _cef_escape(value):
        return str(value).replace("\\", "\\\\").replace("|", "\\|")

    @staticmethod
    def _severity_label(severity):
        if severity <= 2:
            return "info"
        elif severity <= 4:
            return "low"
        elif severity <= 6:
            return "medium"
        elif severity <= 8:
            return "high"
        return "critical"

    def _write_line(self, line):
        """Write a log line with thread safety and size rotation."""
        with self._lock:
            try:
                if os.path.exists(self.output_path):
                    size_mb = os.path.getsize(self.output_path) / (1024 * 1024)
                    if size_mb >= self.max_file_size_mb:
                        rotated = f"{self.output_path}.{int(time.time())}"
                        os.rename(self.output_path, rotated)
            except Exception as e:
                logger.warning(f"[SIEM] Rotation check failed: {e}")
            try:
                with open(self.output_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception as e:
                logger.error(f"[SIEM] Failed to write event: {e}")

    @property
    def stats(self):
        if not os.path.exists(self.output_path):
            return {"lines": 0, "size_kb": 0, "format": self.log_format}
        size = os.path.getsize(self.output_path)
        with open(self.output_path, "r", encoding="utf-8") as f:
            lines = sum(1 for _ in f)
        return {"lines": lines, "size_kb": round(size / 1024, 1),
                "format": self.log_format, "output_path": self.output_path}
