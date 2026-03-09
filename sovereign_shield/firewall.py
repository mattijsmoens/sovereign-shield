"""
Firewall - Identity Gateway and DDoS Protection
================================================
Provides user whitelisting, sliding-window rate limiting, and automatic
blocking with disk-persisted state.

All operations are thread-safe. The block ledger is persisted to disk
so that blocked users remain blocked across process restarts.

Original Source: Extracted from KAIROS Autonomous Intelligence System (modules/communicator.py)
"""

import logging
import time
import json
import os
import threading

logger = logging.getLogger(__name__)


class Firewall:
    """
    Identity-based access control with DDoS protection.
    
    Combines two security layers:
    
        1. Identity Whitelist: Only pre-approved user IDs can interact.
           If no whitelist is configured, all users are allowed.
        
        2. Rate Limiter: Sliding-window algorithm that counts messages
           within a configurable time window. Users who exceed the limit
           are automatically blocked for a configurable duration.
    
    The block ledger is persisted to a JSON file on disk, ensuring that
    blocked users remain blocked even if the process restarts.
    
    Usage:
        fw = Firewall(
            allowed_users=[12345],
            rate_limit=10,
            window=60,
            block_duration=300,
            ledger_path="./data/ddos_ledger.json"
        )
        
        allowed, reason = fw.check(user_id)
        if not allowed:
            print(f"Access denied: {reason}")
    """

    def __init__(self, allowed_users=None, rate_limit=10, window=60,
                 block_duration=300, ledger_path="data/ddos_ledger.json"):
        """
        Initialize the firewall.
        
        Args:
            allowed_users: List of authorized user IDs. If None, all users are allowed.
            rate_limit: Maximum number of messages allowed within the time window.
            window: Rate limit window in seconds.
            block_duration: Duration in seconds to block violators.
            ledger_path: File path for the persistent block ledger.
        """
        self.allowed_users = set(allowed_users) if allowed_users else None
        self.rate_limit = rate_limit
        self.window = window
        self.block_duration = block_duration
        self.ledger_path = ledger_path

        self._lock = threading.Lock()
        self.blocked_users = {}      # {str(user_id): expiry_timestamp}
        self.rate_limit_store = {}   # {str(user_id): [timestamp, ...]}

        # Load any existing block state from disk
        self._load_ledger()

    # ---------------------------------------------------------------
    # LEDGER PERSISTENCE
    # The block ledger survives process restarts by writing to disk
    # after every state change. This prevents attackers from simply
    # restarting the service to clear their block.
    # ---------------------------------------------------------------
    def _load_ledger(self):
        """Load the persisted block ledger from disk."""
        try:
            if os.path.exists(self.ledger_path):
                with open(self.ledger_path, "r") as f:
                    ledger = json.load(f)
                    self.blocked_users = ledger.get("blocked", {})
                    self.rate_limit_store = ledger.get("history", {})
        except Exception as e:
            logger.warning(f"[Firewall] Could not load ledger: {e}")
            self.blocked_users = {}
            self.rate_limit_store = {}

    def _save_ledger(self):
        """Persist the current block state to disk."""
        try:
            ledger_dir = os.path.dirname(self.ledger_path)
            if ledger_dir:
                os.makedirs(ledger_dir, exist_ok=True)
            with open(self.ledger_path, "w") as f:
                json.dump({
                    "blocked": self.blocked_users,
                    "history": self.rate_limit_store
                }, f)
        except Exception as e:
            logger.error(f"[Firewall] Failed to save ledger: {e}")

    # ---------------------------------------------------------------
    # IDENTITY VERIFICATION
    # ---------------------------------------------------------------
    def is_authorized(self, user_id):
        """
        Check if a user is on the whitelist.
        
        If no whitelist is configured (allowed_users=None), all users
        are considered authorized.
        
        Args:
            user_id: The user's identifier.
            
        Returns:
            True if authorized.
        """
        if self.allowed_users is None:
            return True
        if user_id not in self.allowed_users:
            logger.warning(f"[Firewall] Unauthorized access attempt: user {user_id}")
            return False
        return True

    # ---------------------------------------------------------------
    # RATE LIMITER
    # Uses a sliding-window algorithm. For each user, timestamps of
    # recent messages are stored. Messages older than the window are
    # discarded. If the remaining count exceeds the limit, the user
    # is blocked and the block is persisted to disk.
    # ---------------------------------------------------------------
    def check_rate_limit(self, user_id):
        """
        Apply sliding-window rate limiting with automatic blocking.
        
        Args:
            user_id: The user's identifier.
            
        Returns:
            tuple: (allowed: bool, reason: str)
        """
        now = time.time()
        str_uid = str(user_id)

        with self._lock:
            # Step 1: Check if currently blocked
            if str_uid in self.blocked_users:
                expiry = self.blocked_users[str_uid]
                if now < expiry:
                    remaining = int(expiry - now)
                    return False, f"Blocked for rate limit violation. Expires in {remaining}s."
                else:
                    # Block has expired; remove it
                    del self.blocked_users[str_uid]

            # Step 2: Initialize user's history if not present
            if str_uid not in self.rate_limit_store:
                self.rate_limit_store[str_uid] = []

            # Step 3: Sliding window cleanup — discard timestamps outside the window
            timestamps = [t for t in self.rate_limit_store[str_uid] if now - t < self.window]
            self.rate_limit_store[str_uid] = timestamps

            # Step 4: Check if limit is exceeded
            if len(timestamps) >= self.rate_limit:
                self.blocked_users[str_uid] = now + self.block_duration
                logger.warning(
                    f"[Firewall] Rate limit exceeded for user {user_id}. "
                    f"Blocked for {self.block_duration}s."
                )
                self._save_ledger()
                return False, f"Rate limit exceeded. Blocked for {self.block_duration}s."

            # Step 5: Record this message timestamp
            timestamps.append(now)
            self.rate_limit_store[str_uid] = timestamps
            self._save_ledger()

            return True, "Allowed"

    # ---------------------------------------------------------------
    # COMBINED CHECK
    # ---------------------------------------------------------------
    def check(self, user_id):
        """
        Perform a full security check: identity verification + rate limiting.
        
        This is the primary entry point. Call this for every incoming request.
        
        Args:
            user_id: The user's identifier.
            
        Returns:
            tuple: (allowed: bool, reason: str)
        """
        if not self.is_authorized(user_id):
            return False, "Unauthorized user."
        return self.check_rate_limit(user_id)

    # ---------------------------------------------------------------
    # ADMINISTRATIVE OPERATIONS
    # ---------------------------------------------------------------
    def unblock(self, user_id):
        """
        Manually unblock a user.
        
        Args:
            user_id: The user's identifier.
            
        Returns:
            True if the user was blocked and is now unblocked. False if not blocked.
        """
        str_uid = str(user_id)
        with self._lock:
            if str_uid in self.blocked_users:
                del self.blocked_users[str_uid]
                self._save_ledger()
                logger.info(f"[Firewall] User {user_id} manually unblocked.")
                return True
        return False

    def get_blocked_users(self):
        """
        Return a dict of currently blocked users and their block expiry timestamps.
        
        Expired blocks are filtered out.
        
        Returns:
            dict: {str(user_id): expiry_timestamp}
        """
        now = time.time()
        return {uid: exp for uid, exp in self.blocked_users.items() if exp > now}
