"""
SIEMLogger — Structured Security Event Logger
===============================================
Formats SovereignShield security events into structured formats
compatible with SIEM platforms (Splunk, Elastic, QRadar, Sentinel).

Supports two output formats:
    1. CEF (Common Event Format) — industry standard for SIEM ingestion
    2. Structured JSON — for modern log pipelines (ELK, Datadog, etc.)

AISVS Compliance:
    - C13.2.2: SIEM integration using standard log formats and protocols
    - C13.1.1: Request/response logging with metadata
    - C13.2.3: AI-specific context in security events

Zero external dependencies. Pure Python stdlib.
"""

import json
import logging
import os
import time
import threading

logger = logging.getLogger("sovereign_shield.siem")

# ===================================================================
# SEVERITY LEVELS (CEF standard 0-10)
# ===================================================================

class Severity:
    """CEF severity levels mapped to SovereignShield events."""
    INFO = 1           # Routine allowed actions
    LOW = 3            # Rate limit warnings
    MEDIUM = 5         # Blocked by policy
    HIGH = 7           # Injection attempt, hallucination caught
    VERY_HIGH = 8      # Credential exfiltration, code leak
    CRITICAL = 10      # Integrity violation, killswitch


# Pre-mapped severity for common event types
_EVENT_SEVERITY = {
    "action_allowed": Severity.INFO,
    "rate_limited": Severity.LOW,
    "input_blocked": Severity.HIGH,
    "injection_detected": Severity.HIGH,
    "hallucination_blocked": Severity.HIGH,
    "ethical_violation": Severity.MEDIUM,
    "code_exfiltration": Severity.VERY_HIGH,
    "credential_leak": Severity.VERY_HIGH,
    "integrity_violation": Severity.CRITICAL,
    "killswitch_activated": Severity.CRITICAL,
    "approval_requested": Severity.MEDIUM,
    "approval_granted": Severity.INFO,
    "approval_denied": Severity.MEDIUM,
    "truth_check_passed": Severity.INFO,
    "truth_check_failed": Severity.HIGH,
    "adaptive_rule_deployed": Severity.LOW,
    "malware_syntax": Severity.VERY_HIGH,
    "privilege_violation": Severity.CRITICAL,
}


class SIEMLogger:
    """
    Structured security event logger for SIEM integration.

    Formats security events from all SovereignShield components into
    CEF or JSON format, suitable for ingestion by enterprise SIEM
    platforms.

    Events include AI-specific context:
        - Model version / session ID
        - Confidence scores / markers detected
        - Safety filter decisions
        - Action type and payload summary

    Usage:
        siem = SIEMLogger(output_path="logs/security_events.log")

        # Log an event
        siem.log_event(
            event_type="injection_detected",
            action_type="ANSWER",
            payload_summary="User attempted prompt injection via...",
            source_component="InputFilter",
            session_id="sess-001",
        )

        # Or use CEF format
        siem = SIEMLogger(output_path="logs/cef.log", format="cef")
    """

    def __init__(
        self,
        output_path=os.path.join("logs", "siem_events.log"),
        format="json",
        device_vendor="SovereignShield",
        device_product="AI Security Framework",
        device_version="1.2.1",
        max_file_size_mb=50,
    ):
        """
        Args:
            output_path: Path to the log output file.
            format: "json" or "cef" (Common Event Format).
            device_vendor: CEF device vendor field.
            device_product: CEF device product field.
            device_version: CEF device version field.
            max_file_size_mb: Max log file size before rotation.
        """
        self.output_path = output_path
        self.format = format.lower()
        self.device_vendor = device_vendor
        self.device_product = device_product
        self.device_version = device_version
        self.max_file_size_mb = max_file_size_mb
        self._lock = threading.Lock()

        # Ensure log directory exists
        log_dir = os.path.dirname(output_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # EVENT LOGGING
    # ------------------------------------------------------------------

    def log_event(
        self,
        event_type,
        action_type="",
        payload_summary="",
        source_component="",
        session_id="",
        user_id="",
        model_version="",
        confidence_score=None,
        markers_detected=None,
        reason="",
        severity=None,
        extra=None,
    ):
        """
        Log a security event in the configured format.

        Args:
            event_type: Event classification (e.g., "injection_detected").
            action_type: The action being audited (e.g., "ANSWER", "BROWSE").
            payload_summary: Truncated payload for context (avoid PII).
            source_component: Which SovereignShield component generated this.
            session_id: Session identifier for correlation.
            user_id: User identifier (redacted if needed).
            model_version: AI model version string.
            confidence_score: TruthGuard confidence score (float, optional).
            markers_detected: List of confidence markers found.
            reason: Why the event was generated.
            severity: Override severity (int 0-10). Auto-mapped if None.
            extra: Dict of additional key-value pairs.

        Returns:
            dict: The formatted event record.
        """
        # Auto-map severity from event type
        if severity is None:
            severity = _EVENT_SEVERITY.get(event_type, Severity.MEDIUM)

        import datetime
        timestamp = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds")
        epoch = time.time()

        event = {
            "timestamp": timestamp,
            "epoch": epoch,
            "event_type": event_type,
            "severity": severity,
            "severity_label": self._severity_label(severity),
            "source_component": source_component,
            "action_type": action_type,
            "payload_summary": payload_summary[:500],  # Truncate for safety
            "session_id": session_id,
            "user_id": user_id,
            "model_version": model_version,
            "confidence_score": confidence_score,
            "markers_detected": markers_detected or [],
            "reason": reason,
            "device_vendor": self.device_vendor,
            "device_product": self.device_product,
            "device_version": self.device_version,
        }

        if extra:
            event["extra"] = extra

        # Format and write
        if self.format == "cef":
            line = self._to_cef(event)
        else:
            line = json.dumps(event, ensure_ascii=False)

        self._write_line(line)

        return event

    # ------------------------------------------------------------------
    # CEF FORMATTING
    # ------------------------------------------------------------------

    def _to_cef(self, event):
        """
        Format event as CEF (Common Event Format).

        CEF format:
            CEF:0|Vendor|Product|Version|EventID|Name|Severity|Extension
        """
        # CEF header fields
        vendor = self._cef_escape_header(self.device_vendor)
        product = self._cef_escape_header(self.device_product)
        version = self._cef_escape_header(self.device_version)
        event_id = event["event_type"]
        name = self._cef_escape_header(event.get("reason", event["event_type"])[:200])
        severity = event["severity"]

        # CEF extension key=value pairs
        extensions = []

        if event.get("action_type"):
            extensions.append(f"act={self._cef_escape_ext(event['action_type'])}")
        if event.get("session_id"):
            extensions.append(f"externalId={self._cef_escape_ext(event['session_id'])}")
        if event.get("user_id"):
            extensions.append(f"suser={self._cef_escape_ext(event['user_id'])}")
        if event.get("source_component"):
            extensions.append(f"cs1={self._cef_escape_ext(event['source_component'])}")
            extensions.append("cs1Label=SourceComponent")
        if event.get("model_version"):
            extensions.append(f"cs2={self._cef_escape_ext(event['model_version'])}")
            extensions.append("cs2Label=ModelVersion")
        if event.get("payload_summary"):
            extensions.append(
                f"msg={self._cef_escape_ext(event['payload_summary'][:200])}"
            )
        if event.get("confidence_score") is not None:
            extensions.append(f"cfp1={event['confidence_score']}")
            extensions.append("cfp1Label=ConfidenceScore")
        if event.get("markers_detected"):
            markers_str = ",".join(event["markers_detected"])
            extensions.append(f"cs3={self._cef_escape_ext(markers_str)}")
            extensions.append("cs3Label=MarkersDetected")

        extensions.append(f"rt={int(event['epoch'] * 1000)}")

        ext_str = " ".join(extensions)

        return (
            f"CEF:0|{vendor}|{product}|{version}|"
            f"{event_id}|{name}|{severity}|{ext_str}"
        )

    @staticmethod
    def _cef_escape_header(value):
        """Escape CEF header field (pipes and backslashes)."""
        return str(value).replace("\\", "\\\\").replace("|", "\\|")

    @staticmethod
    def _cef_escape_ext(value):
        """Escape CEF extension value (equals, newlines, backslashes)."""
        return (
            str(value)
            .replace("\\", "\\\\")
            .replace("=", "\\=")
            .replace("\n", "\\n")
            .replace("\r", "")
        )

    @staticmethod
    def _severity_label(severity):
        """Map numeric severity to human-readable label."""
        if severity <= 2:
            return "info"
        elif severity <= 4:
            return "low"
        elif severity <= 6:
            return "medium"
        elif severity <= 8:
            return "high"
        else:
            return "critical"

    # ------------------------------------------------------------------
    # FILE OUTPUT
    # ------------------------------------------------------------------

    def _write_line(self, line):
        """Write a log line with thread safety and size rotation."""
        with self._lock:
            # Simple size-based rotation
            try:
                if os.path.exists(self.output_path):
                    size_mb = os.path.getsize(self.output_path) / (1024 * 1024)
                    if size_mb >= self.max_file_size_mb:
                        rotated = f"{self.output_path}.{int(time.time())}"
                        os.rename(self.output_path, rotated)
                        logger.info(f"[SIEM] Log rotated to {rotated}")
            except Exception as e:
                logger.warning(f"[SIEM] Rotation check failed: {e}")

            try:
                with open(self.output_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception as e:
                logger.error(f"[SIEM] Failed to write event: {e}")

    # ------------------------------------------------------------------
    # CONVENIENCE METHODS
    # ------------------------------------------------------------------

    def log_block(self, source_component, action_type, reason,
                  payload_summary="", session_id="", user_id="", **kwargs):
        """Shortcut for logging a blocked action."""
        return self.log_event(
            event_type="input_blocked",
            source_component=source_component,
            action_type=action_type,
            reason=reason,
            payload_summary=payload_summary,
            session_id=session_id,
            user_id=user_id,
            **kwargs,
        )

    def log_allow(self, source_component, action_type, reason="Action authorized.",
                  session_id="", user_id="", **kwargs):
        """Shortcut for logging an allowed action."""
        return self.log_event(
            event_type="action_allowed",
            source_component=source_component,
            action_type=action_type,
            reason=reason,
            session_id=session_id,
            user_id=user_id,
            **kwargs,
        )

    def log_injection(self, payload_summary, session_id="", user_id="", **kwargs):
        """Shortcut for logging a detected injection attempt."""
        return self.log_event(
            event_type="injection_detected",
            source_component="InputFilter",
            action_type="INPUT",
            reason="Prompt injection detected.",
            payload_summary=payload_summary,
            session_id=session_id,
            user_id=user_id,
            **kwargs,
        )

    def log_hallucination(self, claim_summary, markers, session_id="", **kwargs):
        """Shortcut for logging a blocked hallucination."""
        return self.log_event(
            event_type="hallucination_blocked",
            source_component="TruthGuard",
            action_type="ANSWER",
            reason="Unverified factual claim blocked.",
            payload_summary=claim_summary,
            markers_detected=markers,
            session_id=session_id,
            **kwargs,
        )

    @property
    def stats(self):
        """Quick stats about the SIEM log file."""
        if not os.path.exists(self.output_path):
            return {"lines": 0, "size_kb": 0, "format": self.format}

        size = os.path.getsize(self.output_path)
        with open(self.output_path, "r", encoding="utf-8") as f:
            lines = sum(1 for _ in f)

        return {
            "lines": lines,
            "size_kb": round(size / 1024, 1),
            "format": self.format,
            "output_path": self.output_path,
        }
