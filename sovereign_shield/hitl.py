"""
HITLApproval — Human-in-the-Loop Approval Workflow
====================================================
Implements pause-and-approve for high-impact actions.

Instead of a binary ALLOW/BLOCK decision, CoreSafety can now return
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


# ===================================================================
# APPROVAL STATUS ENUM
# ===================================================================

class ApprovalStatus:
    """Status constants for approval requests."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class HITLApproval:
    """
    Human-in-the-Loop approval workflow for high-impact actions.

    When an action matches the high-impact list, instead of blocking it,
    the system pauses execution and returns the action details for human
    review. The action parameters are integrity-bound — approving one
    set of parameters cannot be replayed for different parameters.

    AISVS C9.2.2: "Verify that approval requests present the exact action
    parameters and bind approvals to those parameters to prevent 'approve
    one thing, execute another.'"

    Usage:
        hitl = HITLApproval()

        # Check if action needs approval
        result = hitl.check_action("DEPLOY", "production-server-01")
        if result["status"] == "approval_required":
            # Present to human: result["approval_id"], result["action_details"]
            # Human approves:
            hitl.approve(result["approval_id"])
            # Now re-check:
            result = hitl.execute_approved(result["approval_id"],
                                           "DEPLOY", "production-server-01")
    """

    # Default high-impact actions that require human approval
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
                                Defaults to common high-impact actions.
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

        # In-memory approval store: {approval_id: {...}}
        self._approvals = {}

        # Load persisted state
        self._load_ledger()
        # Prune old completed/expired entries
        self._cleanup_expired()

    def _cleanup_expired(self, max_age_seconds=86400):
        """
        Remove completed/expired entries older than max_age_seconds from memory.
        Keeps the dict bounded in long-running processes.
        """
        now = time.time()
        to_remove = []
        for aid, req in self._approvals.items():
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

    # ------------------------------------------------------------------
    # LEDGER PERSISTENCE
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # PARAMETER BINDING
    # ------------------------------------------------------------------

    @staticmethod
    def _bind_parameters(action_type, payload):
        """
        Create a cryptographic binding of action parameters.

        AISVS C9.2.2: Bind approvals to exact parameters so that
        approving one action cannot be replayed for a different action.
        """
        binding = f"{action_type}|{payload}"
        return hashlib.sha256(binding.encode()).hexdigest()

    # ------------------------------------------------------------------
    # ACTION CHECK
    # ------------------------------------------------------------------

    def check_action(self, action_type, payload, invoker="Unknown"):
        """
        Check if an action requires human approval.

        Args:
            action_type: The action name (e.g., "DEPLOY", "DELETE_FILE").
            payload: The action parameters (target, arguments, etc.).
            invoker: Who/what triggered this action.

        Returns:
            dict with keys:
                - status: "allowed" | "approval_required"
                - approval_id: str (if approval_required)
                - action_details: dict (if approval_required)
                - parameter_hash: str (cryptographic binding)
        """
        action_upper = str(action_type).upper()

        # Not high-impact → allow immediately
        if action_upper not in self.high_impact_actions:
            return {
                "status": "allowed",
                "approval_id": None,
                "action_details": None,
                "parameter_hash": None,
            }

        # High-impact → create approval request
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

    # ------------------------------------------------------------------
    # APPROVAL / DENIAL
    # ------------------------------------------------------------------

    def approve(self, approval_id, approved_by="admin"):
        """
        Approve a pending action.

        Args:
            approval_id: The approval request ID.
            approved_by: Identity of the approver.

        Returns:
            tuple: (success: bool, reason: str)
        """
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
        """
        Deny a pending action.

        Args:
            approval_id: The approval request ID.
            denied_by: Identity of the denier.

        Returns:
            tuple: (success: bool, reason: str)
        """
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

    # ------------------------------------------------------------------
    # EXECUTE APPROVED ACTION
    # ------------------------------------------------------------------

    def execute_approved(self, approval_id, action_type, payload):
        """
        Verify that an approved action matches the original parameters.

        AISVS C9.2.2: Prevents "approve one thing, execute another"
        by verifying the parameter hash matches.

        Args:
            approval_id: The approval ID.
            action_type: The action being executed (must match original).
            payload: The payload being executed (must match original).

        Returns:
            tuple: (allowed: bool, reason: str)
        """
        with self._lock:
            if approval_id not in self._approvals:
                return False, "Approval ID not found."

            request = self._approvals[approval_id]

            if request["status"] != ApprovalStatus.APPROVED:
                return False, f"Request status is '{request['status']}', not approved."

            if time.time() > request["expires_at"]:
                request["status"] = ApprovalStatus.EXPIRED
                self._save_ledger()
                return False, "Approval has expired."

            # Verify parameter binding
            current_hash = self._bind_parameters(
                str(action_type).upper(), payload
            )
            if current_hash != request["parameter_hash"]:
                logger.critical(
                    f"[HITL] PARAMETER MISMATCH: Approved hash "
                    f"{request['parameter_hash'][:16]} != "
                    f"execution hash {current_hash[:16]}"
                )
                return False, (
                    "Parameter mismatch: the action parameters differ from "
                    "what was approved. This may indicate a substitution attack."
                )

        logger.info(f"[HITL] Executing approved action: {approval_id}")
        return True, "Action authorized via human approval."

    # ------------------------------------------------------------------
    # ADMIN
    # ------------------------------------------------------------------

    def get_pending(self):
        """Get all pending approval requests (non-expired)."""
        now = time.time()
        return {
            aid: req for aid, req in self._approvals.items()
            if req["status"] == ApprovalStatus.PENDING
            and now <= req["expires_at"]
        }

    def get_audit_log(self, limit=50):
        """Get the most recent approval decisions."""
        sorted_items = sorted(
            self._approvals.values(),
            key=lambda x: x.get("decided_at") or x["created_at"],
            reverse=True,
        )
        return sorted_items[:limit]

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
        expired = sum(
            1 for r in self._approvals.values()
            if r["status"] == ApprovalStatus.EXPIRED
            or (r["status"] == ApprovalStatus.PENDING and now > r["expires_at"])
        )
        return {
            "pending": pending,
            "approved": approved,
            "denied": denied,
            "expired": expired,
            "total": len(self._approvals),
        }
