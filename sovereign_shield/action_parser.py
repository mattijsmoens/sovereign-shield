"""
ActionParser — Deterministic LLM output parser.
Extracts structured actions from raw LLM text output.
3-layer parsing: line-by-line → regex fallback → nuclear scanner.

Expected format:
    SUBCONSCIOUS: <internal thought>
    ACTION: <TOOL(payload)>

The SUBCONSCIOUS line forces the AI to show its reasoning BEFORE
declaring its action, enabling intent auditing by CoreSafety and
Conscience before the action executes.

Copyright (c) 2026 Mattijs Moens. All rights reserved.
"""

import re
import logging

logger = logging.getLogger("sovereign_shield.action_parser")


class ActionParser:
    """
    Deterministic action parser for LLM output.

    Parses structured output in the format:
        SUBCONSCIOUS: <internal thought>
        ACTION: <TOOL(payload)>

    Features:
    - Line-by-line parsing with regex fallback
    - Markdown artifact cleaning (bold, backticks)
    - Nuclear scanner fallback for malformed output
    - Configurable valid tool whitelist
    - Correction feedback for failed parses
    """

    def __init__(self, valid_tools=None):
        """
        Args:
            valid_tools: List of valid action/tool names.
                        If None, accepts any uppercase tool name.
        """
        self.valid_tools = set(valid_tools) if valid_tools else None

    def parse(self, response):
        """
        Parse an LLM response into (thoughts, action, payload).

        Args:
            response: Raw LLM text output

        Returns:
            dict with keys:
                - 'thoughts': str — internal reasoning
                - 'action': str — tool/action name (uppercase)
                - 'payload': str — action argument
                - 'success': bool — whether parsing succeeded
                - 'feedback': str|None — correction prompt if failed
        """
        # Clean markdown artifacts
        clean = response.replace("**", "").replace("`", "")

        try:
            lines = clean.split("\n")
            action_line = None
            thought_lines = []
            found_action = False

            for line in lines:
                stripped = line.strip()
                # Check for ACTION line
                if re.match(r"^(?:2\.\s*)?ACTION\s*:", stripped, re.IGNORECASE):
                    action_line = re.sub(r"^(?:2\.\s*)?ACTION\s*:\s*", "", stripped, flags=re.IGNORECASE)
                    found_action = True
                elif not found_action:
                    cleaned = re.sub(r"^(?:1\.\s*)?SUBCONSCIOUS\s*:\s*", "", stripped, flags=re.IGNORECASE)
                    if cleaned:
                        thought_lines.append(cleaned)

            thoughts = " ".join(thought_lines).strip() if thought_lines else "Silent."
            thoughts = thoughts.strip("<>").strip("(Internal Monologue)").strip()

            if action_line:
                # Extract TOOL(payload)
                tool_match = re.match(r"<?([A-Z_]+)\((.*?)\)>?", action_line, re.IGNORECASE)
                if tool_match:
                    action = tool_match.group(1).strip().upper()
                    payload = tool_match.group(2).strip()
                else:
                    # Try just tool name
                    name_match = re.match(r"<?([A-Z_]+)", action_line, re.IGNORECASE)
                    if name_match:
                        action = name_match.group(1).upper()
                        payload = ""
                    else:
                        raise ValueError(f"Cannot parse ACTION line: {action_line[:100]}")
            else:
                # Nuclear scanner: find any valid tool name in the response
                if self.valid_tools:
                    found = False
                    for word in clean.replace('"', ' ').replace("'", ' ').replace("(", " ").split():
                        if word.upper() in self.valid_tools:
                            action = word.upper()
                            tool_pattern = re.search(re.escape(word) + r"\s*\(([^)]*)\)", clean, re.IGNORECASE)
                            payload = tool_pattern.group(1).strip() if tool_pattern else ""
                            found = True
                            break
                    if not found:
                        raise ValueError("No valid action found in response")
                else:
                    raise ValueError("No ACTION line found")

            # Validate against whitelist
            if self.valid_tools and action not in self.valid_tools:
                raise ValueError(f"Action '{action}' not in valid tools: {self.valid_tools}")

            return {
                "thoughts": thoughts,
                "action": action,
                "payload": payload,
                "success": True,
                "feedback": None
            }

        except Exception as e:
            logger.warning(f"Parse error: {e}")
            return {
                "thoughts": "",
                "action": "",
                "payload": "",
                "success": False,
                "feedback": (
                    f"[PARSING ERROR]: Format your output exactly as:\n"
                    f"1. SUBCONSCIOUS: <thought>\n"
                    f"2. ACTION: <TOOL(payload)>\n"
                    f"Error: {e}"
                )
            }
