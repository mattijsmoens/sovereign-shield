"""
Firewall — Identity Whitelisting & Rate Limiting
==================================================
Provides per-user rate limiting and optional identity whitelisting
for the SovereignShield SaaS API.

Zero external dependencies. Pure Python stdlib.
"""

import json
import logging
import os
import threading
import time

logger = logging.getLogger("sovereign_shield.firewall")


class Firewall:
    """
    Rate limiter and identity gatekeeper.

    Args:
        allowed_users: Set/list of allowed user IDs (None = allow all)
        rate_limit: Max requests per window
        window: Window size in seconds (default: 60)
        block_duration: Seconds to block after rate limit exceeded (default: 300)
        ledger_path: Path for persistent rate limit state
    """

    def __init__(self, allowed_users=None, rate_limit=60, window=60,
                 block_duration=300, ledger_path=None):
        self.allowed_users = set(allowed_users) if allowed_users else None
        self.rate_limit = rate_limit
        self.window = window
        self.block_duration = block_duration
        self.ledger_path = ledger_path
        self._lock = threading.Lock()
        self._requests = {}   # {user_id: [timestamps]}
        self._blocked = {}    # {user_id: unblock_time}

    def check_identity(self, user_id):
        """Check if a user is on the whitelist. Returns (allowed, reason)."""
        if self.allowed_users is None:
            return True, "No whitelist configured."
        if user_id in self.allowed_users:
            return True, "Identity verified."
        return False, f"User '{user_id}' not in whitelist."

    def check_rate_limit(self, user_id):
        """Check rate limit for a user. Returns (allowed, reason)."""
        with self._lock:
            now = time.time()

            # Check if user is currently blocked
            if user_id in self._blocked:
                if now < self._blocked[user_id]:
                    remaining = int(self._blocked[user_id] - now)
                    return False, f"Rate limited. Try again in {remaining}s."
                else:
                    del self._blocked[user_id]

            # Clean old timestamps
            if user_id not in self._requests:
                self._requests[user_id] = []
            self._requests[user_id] = [
                t for t in self._requests[user_id]
                if now - t < self.window
            ]

            # Check limit
            if len(self._requests[user_id]) >= self.rate_limit:
                self._blocked[user_id] = now + self.block_duration
                return False, (
                    f"Rate limit exceeded ({self.rate_limit}/{self.window}s). "
                    f"Blocked for {self.block_duration}s."
                )

            # Record request
            self._requests[user_id].append(now)
            return True, "OK"

    def gate(self, user_id):
        """Combined identity + rate limit check. Returns (allowed, reason)."""
        ok, reason = self.check_identity(user_id)
        if not ok:
            return False, reason
        return self.check_rate_limit(user_id)
