"""
HITLApproval — Human-in-the-Loop Approval Workflow
====================================================================
Implements pause-and-approve for high-impact actions.

Instead of a binary ALLOW/BLOCK decision, SovereignShield can return
APPROVAL_REQUIRED for actions that match a configurable high-impact
action list. The developer integrates a callback to present the action
details to a human reviewer and collect their decision.

AISVS Compliance:
    - C9.2: High-Impact Action Approval and Irreversibility Controls
    - C14.2: Human-in-the-Loop Decision Checkpoints

Zero external dependencies. Pure Python stdlib.
"""

import hashlib
import json
import logging
import os
import threading
import time
import uuid

logger = logging.getLogger("sovereign_shield.hitl")


class ApprovalStatus:
    """Status constants for approval requests."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CONSUMED = "consumed"


class HITLApproval:
    """
    Human-in-the-Loop approval workflow for high-impact actions.

    When an action matches the high-impact list, instead of blocking it,
    the system pauses execution and returns the action details for human
    review. The action parameters are integrity-bound — approving one
    set of parameters cannot be replayed for different parameters.

    Usage:
        hitl = HITLApproval()

        result = hitl.check_action("DEPLOY", "production-server-01")
        if result["status"] == "approval_required":
            hitl.approve(result["approval_id"])
            result = hitl.execute_approved(result["approval_id"],
                                           "DEPLOY", "production-server-01")
    """

    DEFAULT_HIGH_IMPACT = {
        "DEPLOY", "DELETE_FILE", "DROP_DATABASE", "MERGE_CODE",
        "TRANSFER_FUNDS", "MODIFY_ACCESS", "SEND_EMAIL",
        "PUBLISH", "EXECUTE_MIGRATION", "REVOKE_KEY",
        "SHUTDOWN", "RESTART", "ESCALATE_PRIVILEGES",
    }

    def __init__(
        self,
        high_impact_actions=None,
        approval_ttl_seconds=300,
        ledger_path=os.path.join("data", "hitl_ledger.json"),
    ):
        """
        Args:
            high_impact_actions: Set of action types requiring human approval.
            approval_ttl_seconds: How long an approval remains valid (default: 5 min).
            ledger_path: File path for persistent approval ledger.
        """
        self.high_impact_actions = (
            set(high_impact_actions) if high_impact_actions
            else self.DEFAULT_HIGH_IMPACT
        )
        self.approval_ttl = approval_ttl_seconds
        self.ledger_path = ledger_path
        self._lock = threading.Lock()
        self._approvals = {}
        self._load_ledger()
        self._cleanup_expired()

    def _cleanup_expired(self, max_age_seconds=86400):
        """Remove completed/expired entries older than max_age_seconds."""
        with self._lock:
            now = time.time()
            to_remove = []
            for aid, req in list(self._approvals.items()):
                age = now - req.get("created_at", now)
                if age > max_age_seconds and req["status"] != ApprovalStatus.PENDING:
                    to_remove.append(aid)
                elif req["status"] == ApprovalStatus.PENDING and now > req.get("expires_at", now):
                    req["status"] = ApprovalStatus.EXPIRED
                    to_remove.append(aid)
            if to_remove:
                for aid in to_remove:
                    del self._approvals[aid]
                self._save_ledger()
                logger.debug(f"[HITL] Cleaned up {len(to_remove)} old approval entries.")

    def _load_ledger(self):
        """Load persisted approval state from disk."""
        try:
            if os.path.exists(self.ledger_path):
                with open(self.ledger_path, "r", encoding="utf-8") as f:
                    self._approvals = json.load(f)
        except Exception as e:
            logger.warning(f"[HITL] Could not load ledger: {e}")
            self._approvals = {}

    def _save_ledger(self):
        """Persist approval state to disk."""
        try:
            ledger_dir = os.path.dirname(self.ledger_path)
            if ledger_dir:
                os.makedirs(ledger_dir, exist_ok=True)
            with open(self.ledger_path, "w", encoding="utf-8") as f:
                json.dump(self._approvals, f, indent=2)
        except Exception as e:
            logger.error(f"[HITL] Failed to save ledger: {e}")

    @staticmethod
    def _bind_parameters(action_type, payload):
        """Create cryptographic binding of action parameters."""
        binding = f"{action_type}|{payload}"
        return hashlib.sha256(binding.encode()).hexdigest()

    def check_action(self, action_type, payload, invoker="Unknown"):
        """
        Check if an action requires human approval.

        Returns:
            dict with: status, approval_id, action_details, parameter_hash
        """
        action_upper = str(action_type).upper()

        if action_upper not in self.high_impact_actions:
            return {
                "status": "allowed",
                "approval_id": None,
                "action_details": None,
                "parameter_hash": None,
            }

        approval_id = uuid.uuid4().hex[:12]
        param_hash = self._bind_parameters(action_upper, payload)

        request = {
            "approval_id": approval_id,
            "action_type": action_upper,
            "payload": str(payload),
            "invoker": invoker,
            "parameter_hash": param_hash,
            "status": ApprovalStatus.PENDING,
            "created_at": time.time(),
            "expires_at": time.time() + self.approval_ttl,
            "decided_at": None,
            "decided_by": None,
        }

        with self._lock:
            self._approvals[approval_id] = request
            self._save_ledger()

        logger.info(
            f"[HITL] Approval required: {action_upper} by {invoker}. "
            f"ID: {approval_id}"
        )

        return {
            "status": "approval_required",
            "approval_id": approval_id,
            "action_details": {
                "action_type": action_upper,
                "payload": str(payload),
                "invoker": invoker,
                "expires_in_seconds": self.approval_ttl,
            },
            "parameter_hash": param_hash,
        }

    def approve(self, approval_id, approved_by="admin"):
        """Approve a pending action. Returns (success, reason)."""
        with self._lock:
            if approval_id not in self._approvals:
                return False, "Approval ID not found."
            request = self._approvals[approval_id]
            if request["status"] != ApprovalStatus.PENDING:
                return False, f"Request already {request['status']}."
            if time.time() > request["expires_at"]:
                request["status"] = ApprovalStatus.EXPIRED
                self._save_ledger()
                return False, "Approval request has expired."
            request["status"] = ApprovalStatus.APPROVED
            request["decided_at"] = time.time()
            request["decided_by"] = approved_by
            self._save_ledger()
        logger.info(f"[HITL] Approved: {approval_id} by {approved_by}")
        return True, "Approved."

    def deny(self, approval_id, denied_by="admin"):
        """Deny a pending action. Returns (success, reason)."""
        with self._lock:
            if approval_id not in self._approvals:
                return False, "Approval ID not found."
            request = self._approvals[approval_id]
            if request["status"] != ApprovalStatus.PENDING:
                return False, f"Request already {request['status']}."
            request["status"] = ApprovalStatus.DENIED
            request["decided_at"] = time.time()
            request["decided_by"] = denied_by
            self._save_ledger()
        logger.info(f"[HITL] Denied: {approval_id} by {denied_by}")
        return True, "Denied."

    def execute_approved(self, approval_id, action_type, payload):
        """Verify approved action matches original parameters. Returns (allowed, reason).

        Approval is consumed after successful execution to prevent replay attacks.
        """
        with self._lock:
            if approval_id not in self._approvals:
                return False, "Approval ID not found."
            request = self._approvals[approval_id]
            if request["status"] == ApprovalStatus.CONSUMED:
                return False, "Approval already consumed. Cannot replay."
            if request["status"] != ApprovalStatus.APPROVED:
                return False, f"Request status is '{request['status']}', not approved."
            if time.time() > request["expires_at"]:
                request["status"] = ApprovalStatus.EXPIRED
                self._save_ledger()
                return False, "Approval has expired."
            current_hash = self._bind_parameters(str(action_type).upper(), payload)
            if current_hash != request["parameter_hash"]:
                logger.critical(
                    f"[HITL] PARAMETER MISMATCH: hash mismatch on {approval_id}"
                )
                return False, (
                    "Parameter mismatch: action parameters differ from "
                    "what was approved. Possible substitution attack."
                )
            # Consume the approval to prevent replay attacks
            request["status"] = ApprovalStatus.CONSUMED
            request["executed_at"] = time.time()
            self._save_ledger()
        logger.info(f"[HITL] Executing approved action: {approval_id} (consumed)")
        return True, "Action authorized via human approval."

    def get_pending(self):
        """Get all pending approval requests (non-expired)."""
        now = time.time()
        return {
            aid: req for aid, req in self._approvals.items()
            if req["status"] == ApprovalStatus.PENDING
            and now <= req["expires_at"]
        }

    @property
    def stats(self):
        """Quick stats about the HITL system."""
        now = time.time()
        pending = sum(
            1 for r in self._approvals.values()
            if r["status"] == ApprovalStatus.PENDING and now <= r["expires_at"]
        )
        approved = sum(
            1 for r in self._approvals.values()
            if r["status"] == ApprovalStatus.APPROVED
        )
        denied = sum(
            1 for r in self._approvals.values()
            if r["status"] == ApprovalStatus.DENIED
        )
        return {"pending": pending, "approved": approved, "denied": denied,
                "total": len(self._approvals)}
