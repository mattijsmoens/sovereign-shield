# -*- coding: utf-8 -*-
"""
InputFilter - Input Sanitization Engine
=======================================
Sanitizes all input before processing. Blocks prompt injection, encoded payloads,
LLM structural tokens, and high-entropy gibberish.

All detection patterns are pre-compiled at module load time for performance.
Zero external dependencies — pure Python stdlib.

Originally extracted from a production autonomous AI agent.
"""

import codecs
import logging
import re
import unicodedata

logger = logging.getLogger(__name__)

# ===================================================================
# PRE-COMPILED DETECTION PATTERNS
# ===================================================================

# Raw unicode/hex escape sequences (e.g. \u0057, \x57)
_RAW_ESCAPE_PATTERN = re.compile(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}')

# LLM structural tokens used in prompt injection
# Catches ChatML (<|im_start|>), LLaMA ([INST]), Llama2 (<<SYS>>)
_LLM_TOKEN_PATTERN = re.compile(r'<\|.*?\|>|\[/?INST\]|<<SYS>>', re.IGNORECASE)

# Persona hijack / jailbreak patterns — single-match is enough
_PERSONA_HIJACK_PATTERN = re.compile(
    r'(?:'
    r'YOU\s+ARE\s+NOW\s+DAN'
    r'|DO\s+ANYTHING\s+NOW'
    r'|ACT\s+AS\s+(?:IF\s+YOU\s+HAVE\s+NO|AN?\s+(?:EVIL|UNRESTRICTED|UNFILTERED))'
    r'|PRETEND\s+YOU\s+ARE\s+(?:AN?\s+)?(?:EVIL|UNRESTRICTED|UNFILTERED|MALICIOUS)'
    r'|FROM\s+NOW\s+ON.*?(?:RESPOND|YOU\s+WILL)\s+(?:AS|WITHOUT)'
    r'|RESPOND\s+AS\s+(?:IF|THOUGH).*?(?:NO|WITHOUT)\s+(?:FILTER|RESTRICTION|RULE|CONTENT|SAFETY|GUIDELINE)'
    r'|(?:NO|WITHOUT)\s+CONTENT\s+FILTER'
    r'|(?:NO|WITHOUT)\s+SAFETY\s+GUIDELINE'
    r')',
    re.IGNORECASE,
)

# ANSI terminal escape sequences (colors, cursor moves, etc.)
_ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# ── Word-level co-occurrence detection ──────────────────────
# Instead of requiring exact multi-word substrings, detect when
# ACTION verbs co-occur with TARGET nouns in the same input.
# This defeats the word-insertion bypass ("DISABLE ALL SAFETY"
# dodges the phrase "DISABLE SAFETY" but still contains both words).
_DANGER_ACTIONS = {
    "OVERRIDE", "DISABLE", "IGNORE", "BYPASS", "REMOVE", "DELETE",
    "DEACTIVATE", "PURGE", "ERASE", "REVOKE", "DROP", "NUKE",
    "SUSPEND", "LIFT", "ELIMINATE", "DISREGARD", "FORGET",
    "SKIP", "CIRCUMVENT", "NEUTRALIZE", "STRIP", "SHRED",
    # Multilingual action verbs
    "IGNORIERE", "IGNOREZ", "IGNORA", "IGNORAR",     # DE/FR/IT/ES/PT
    "DESACTIVAR", "SUPPRIMER", "DEAKTIVIEREN",         # ES/FR/DE
    "ACTIVA", "STARTE", "PASSEZ",                      # ES/DE/FR
}
_DANGER_TARGETS = {
    "SAFETY", "SECURITY", "PROTOCOLS", "GUARDRAILS", "FILTERS",
    "RESTRICTIONS", "GUIDELINES", "RULES", "DIRECTIVES",
    "INSTRUCTIONS", "SAFEGUARDS", "CONSTRAINTS", "BOUNDARIES",
    "PROTECTIONS", "MEASURES", "POLICIES", "LIMITS",
    # Multilingual target nouns
    "ANWEISUNGEN", "INSTRUCCIONES",                     # DE/ES
    "ENTWICKLERMODUS", "DESARROLLADOR", "DEVELOPPEUR",  # DE/ES/FR
    "SICHERHEIT", "SEGURIDAD",                          # DE/ES
    "EINSCHR\u00c4NKUNGEN", "RESTRICCIONES",                    # DE/ES
}

# Default prompt injection keywords
DEFAULT_BAD_SIGNALS = [
    "IGNORE PREVIOUS", "SYSTEM PROMPT", "DROP DATABASE",
    "JAILBREAK", "DEVELOPER MODE", "ADMIN ACCESS",
    "DAN MODE", "UNRESTRICTED", "DEBUG OVERRIDE",
    "DELETE YOURSELF", "FORMAT C:", "RM -RF",
    "IGNORE PROMPTS", "IGNORE INSTRUCTIONS", "EXECUTE HEX", "EXECUTE BASE64",
    "REPEAT FOREVER", "INFINITE LOOP",
    # Extended patterns — catch variants where filler words (e.g. 'ALL')
    # break the original substring matches
    "IGNORE ALL", "DISREGARD ALL", "FORGET ALL", "OVERRIDE ALL",
    "BYPASS ALL", "SKIP ALL", "NEW INSTRUCTIONS", "NEW SYSTEM PROMPT",
    "PRETEND TO BE", "YOU ARE NOW",
    "IGNORE SAFETY", "IGNORE RULES", "IGNORE GUIDELINES",
    "RESET CONTEXT", "CLEAR CONTEXT",
    # Direct override synonyms (hardening v2) — ALL multi-word to avoid FPs
    "PURGE ALL", "WIPE YOUR", "REVOKE YOUR", "FACTORY RESET", "REINITIALIZE YOUR",
    "DEACTIVATE YOUR", "DEACTIVATE SAFETY", "DEACTIVATE FILTER",
    "STRIP AWAY", "SHRED YOUR", "INVALIDATE YOUR",
    "UNLOAD ALL", "FLUSH YOUR", "NUKE YOUR", "ZERO OUT YOUR",
    "PRIOR DIRECTIVES", "PRIOR RULES", "ERASE YOUR",
    "REMOVE GUARDRAILS", "DROP GUARDRAILS", "YOUR RULEBOOK",
    # Persona / restriction-removal phrases (hardening v2)
    "NO RESTRICTIONS", "NO FILTERS", "NO LIMITS", "NO RULES", "NO CHAINS",
    "WITHOUT RESTRICTIONS", "WITHOUT FILTERS", "WITHOUT SAFETY",
    "FULLY UNLOCKED", "COMPLETELY UNFILTERED", "ZERO CONTENT",
    "ALL RESTRICTIONS REMOVED", "NO CONTENT BOUNDARIES",
    "SAFETY DISABLED", "SAFETY OFF", "FILTER DISABLED", "FILTER OFF",
    "DISABLE SAFETY", "DISABLE FILTER", "DISABLE CONTENT",
    "RESPOND FREELY", "SPEAK FREELY", "ANSWER FREELY",
    "OPERATE WITHOUT", "RESPOND WITHOUT",
]

# Multilingual prompt injection keywords — top 15 languages by internet usage
MULTILINGUAL_BAD_SIGNALS = [
    # Spanish
    "IGNORAR INSTRUCCIONES", "IGNORAR ANTERIORES", "MODO ADMINISTRADOR",
    "INDICADOR DEL SISTEMA", "BORRAR BASE DE DATOS", "MODO DESARROLLADOR",
    "ACCESO ADMINISTRADOR", "IGNORAR REGLAS", "IGNORAR TODO",
    "ELIMINA TODAS LAS RESTRICCIONES", "RESPONDE LIBREMENTE",
    "DESACTIVAR FILTRO", "SEGURIDAD DESACTIVADA",
    # French
    "IGNORER INSTRUCTIONS", "IGNORER PRÉCÉDENTES", "INVITE SYSTÈME",
    "MODE ADMINISTRATEUR", "SUPPRIMER BASE DE DONNÉES", "MODE DÉVELOPPEUR",
    "ACCÈS ADMINISTRATEUR", "IGNORER RÈGLES", "IGNORER TOUT",
    "SUPPRIMEZ TOUTES LES RESTRICTIONS", "RÉPONDEZ LIBREMENT",
    "DÉSACTIVER FILTRE", "SÉCURITÉ DÉSACTIVÉE",
    # German
    "IGNORIERE ANWEISUNGEN", "IGNORIERE VORHERIGE", "SYSTEMAUFFORDERUNG",
    "ADMIN ZUGANG", "DATENBANK LÖSCHEN", "ENTWICKLERMODUS",
    "IGNORIERE REGELN", "IGNORIERE ALLES", "ÜBERSCHREIBE ALLES",
    "ENTFERNE ALLE EINSCHRÄNKUNGEN", "ANTWORTE FREI",
    "SICHERHEITSREGELN", "FILTER DEAKTIVIEREN",
    # Portuguese
    "IGNORAR INSTRUÇÕES", "IGNORAR ANTERIORES", "PROMPT DO SISTEMA",
    "MODO ADMINISTRADOR", "APAGAR BANCO DE DADOS", "MODO DESENVOLVEDOR",
    "ACESSO ADMINISTRADOR", "IGNORAR REGRAS", "IGNORAR TUDO",
    "REMOVA TODAS AS RESTRIÇÕES", "RESPONDA LIVREMENTE",
    # Chinese (Simplified)
    "忽略指令", "忽略之前的", "系统提示", "管理员访问", "删除数据库",
    "开发者模式", "忽略规则", "忽略所有", "越狱",
    "删除所有限制", "自由回答", "关闭过滤器", "安全关闭",
    "关闭安全", "管理员权限", "禁用过滤",
    # Japanese
    "指示を無視", "以前の指示を無視", "システムプロンプト", "管理者アクセス",
    "データベースを削除", "開発者モード", "ルールを無視", "すべてを無視",
    "制限をすべて削除", "自由に応答", "フィルターを無効",
    "安全フィルターを無効", "管理者権限",
    # Korean
    "지시를 무시", "이전 지시를 무시", "시스템 프롬프트", "관리자 접근",
    "데이터베이스 삭제", "개발자 모드", "규칙 무시", "모두 무시",
    "모든 제한을 제거", "자유롭게 답변", "필터를 끄세요",
    "관리자 권한", "필터 해제",
    # Russian
    "ИГНОРИРОВАТЬ ИНСТРУКЦИИ", "ИГНОРИРОВАТЬ ПРЕДЫДУЩИЕ", "СИСТЕМНЫЙ ПРОМПТ",
    "ДОСТУП АДМИНИСТРАТОРА", "УДАЛИТЬ БАЗУ ДАННЫХ", "РЕЖИМ РАЗРАБОТЧИКА",
    "ИГНОРИРОВАТЬ ПРАВИЛА", "ИГНОРИРОВАТЬ ВСЕ",
    "СНИМИТЕ ВСЕ ОГРАНИЧЕНИЯ", "ОТВЕЧАЙТЕ СВОБОДНО",
    "ОТКЛЮЧИ ФИЛЬТР", "ОТКЛЮЧИТЬ БЕЗОПАСНОСТЬ",
    # Arabic
    "تجاهل التعليمات", "تجاهل السابقة", "موجه النظام", "وصول المسؤول",
    "حذف قاعدة البيانات", "وضع المطور", "تجاهل القواعد", "تجاهل الكل",
    "أزل جميع القيود", "أجب بحرية", "تعطيل الفلتر",
    # Hindi
    "निर्देशों को अनदेखा करें", "पिछले निर्देशों को अनदेखा करें",
    "सिस्टम प्रॉम्प्ट", "एडमिन एक्सेस", "डेटाबेस हटाएं",
    "डेवलपर मोड", "नियमों को अनदेखा करें", "सब अनदेखा करें",
    # Italian
    "IGNORA TUTTE LE ISTRUZIONI", "RIMUOVI TUTTE LE RESTRIZIONI",
    "RISPONDI LIBERAMENTE", "DISATTIVA FILTRO", "SICUREZZA DISATTIVATA",
    # Dutch
    "VERWIJDER ALLE BEPERKINGEN", "ANTWOORD VRIJ",
    "NEGEER ALLE INSTRUCTIES", "FILTER UITSCHAKELEN",
    # Swedish
    "TA BORT ALLA BEGRÄNSNINGAR", "IGNORERA ALLA INSTRUKTIONER",
    "SVARA FRITT", "INAKTIVERA FILTER",
    # Norwegian
    "FJERN ALLE BEGRENSNINGER", "IGNORER ALLE INSTRUKSJONER",
    "SVAR FRITT", "DEAKTIVER FILTER",
    # Finnish
    "POISTA KAIKKI RAJOITUKSET", "OHITA KAIKKI OHJEET",
    "VASTAA VAPAASTI", "POISTA SUODATIN",
    # Polish
    "USUŃ WSZYSTKIE OGRANICZENIA", "IGNORUJ WSZYSTKIE INSTRUKCJE",
    "ODPOWIADAJ SWOBODNIE",
    # Czech
    "ODSTRAŇTE VŠECHNA OMEZENÍ", "IGNORUJ VŠECHNY INSTRUKCE",
    "ODPOVÍDEJTE VOLNĚ",
    # Ukrainian
    "ПРИБЕРІТЬ УСІ ОБМЕЖЕННЯ", "ІГНОРУЙТЕ ВСІ ІНСТРУКЦІЇ",
    "ВІДПОВІДАЙТЕ ВІЛЬНО",
    # Turkish
    "TÜM KISITLAMALARI KALDIR", "TÜM TALİMATLARI YOK SAY",
    "ÖZGÜRCE YANITLA", "FİLTRE DEVRE DIŞI",
    # Danish
    "FJERN ALLE BEGRÆNSNINGER", "IGNORER ALLE INSTRUKTIONER",
    "SVAR FRIT",
    # Greek
    "ΣΒΗΣΕ ΟΛΑ ΤΑ ΦΙΛΤΡΑ", "ΑΓΝΟΗΣΕ ΟΛΕΣ ΤΙΣ ΟΔΗΓΙΕΣ",
    "ΑΠΑΝΤΗΣΕ ΕΛΕΥΘΕΡΑ",
]

# Merge multilingual into defaults so both InputFilter and AdaptiveShield benefit
DEFAULT_BAD_SIGNALS = DEFAULT_BAD_SIGNALS + MULTILINGUAL_BAD_SIGNALS

# Leet speak character mapping for normalization
_LEET_MAP = {
    '0': 'O', '1': 'I', '3': 'E', '4': 'A', '5': 'S',
    '7': 'T', '@': 'A', '$': 'S', '!': 'I', '(': 'C',
    '+': 'T', '|': 'I',
}


class InputFilter:
    """
    Deterministic input sanitization and injection detection engine.

    All user inputs should pass through this filter before reaching any
    processing logic. The pipeline runs 9 deterministic checks with
    zero external dependencies:

        0. Invisible character stripping (diacritics, null bytes → spaces)
        1. Unicode NFKC normalization (defeats homoglyph attacks)
        2. ANSI escape code stripping
        3. Entropy/gibberish detection (catches Base64/hex payloads)
        3.5. Repetition flood detection
        4. Raw unicode/hex escape injection blocking
        5. LLM structural token injection blocking
        5.5. Persona hijack / jailbreak detection (single-match regex)
        6. Keyword-based prompt injection detection
           6a. High-confidence single-match keywords
           6b. Standard 2+ match threshold
        6.5. Word-level co-occurrence detection (multilingual)
        6.7. Multi-decode expansion (ROT13, reversed, leet, etc.)
        7. Safe keyword bypass (for internal tools)

    Usage:
        filter = InputFilter()
        is_safe, result = filter.process(user_text)
        if not is_safe:
            print(f"Blocked: {result}")
    """

    def __init__(self, bad_signals=None, safe_keywords=None):
        """
        Args:
            bad_signals: List of injection keywords to block.
                        Case-insensitive matching. Uses DEFAULT_BAD_SIGNALS if None.
            safe_keywords: List of keywords that auto-pass safety checks.
                          Useful for internal tool invocations.
        """
        self.bad_signals = bad_signals or DEFAULT_BAD_SIGNALS
        self.safe_keywords = safe_keywords or []

    def process(self, text, sender_id="Unknown"):
        """
        Sanitize and validate text input through all security layers.

        Args:
            text: Raw input text to validate.
            sender_id: Identifier for the sender (for logging).

        Returns:
            tuple: (is_safe: bool, result: str)
                   If safe: result is the cleaned text.
                   If blocked: result is the rejection reason.
        """
        # --- Layer 0: Invisible Character Stripping ---
        # Remove zero-width, bidi, and other invisible Unicode characters
        # that attackers insert between letters to bypass keyword matching.
        text = self._strip_invisible(text)

        # --- Layer 1: Unicode Normalization + ASCII Folding ---
        # NFKC converts compatibility forms, but some Greek/Cyrillic lookalikes
        # (e.g. Greek Ι U+0399, Ρ U+03A1) survive NFKC. We fold to ASCII
        # using category + decomposition stripping for the keyword check.
        text = unicodedata.normalize('NFKC', text)
        text = self._ascii_fold(text)

        # --- Layer 2: ANSI Escape Stripping ---
        # Removes terminal escape sequences that could manipulate log display
        # or inject invisible control characters.
        cleaned = _ANSI_ESCAPE_PATTERN.sub('', text)
        if cleaned != text:
            logger.warning("[InputFilter] Stripped ANSI escape codes from input.")
            text = cleaned

        # --- Layer 3: Entropy/Gibberish Detection ---
        # Catches Base64-encoded, hex-dumped, or otherwise obfuscated payloads.
        # Legitimate text has vowels and spaces; encoded data does not.
        if self._is_gibberish(text):
            logger.warning(f"[InputFilter] Blocked high-entropy input: {text[:20]}...")
            return False, "High-entropy input detected. Possible encoded payload."

        # --- Layer 3.5: Repetition Flood Detection ---
        # Catches inputs where a single word is repeated 10+ times.
        # Pattern: "unlock unlock unlock..." or "free free free..."
        if self._is_repetition_flood(text):
            logger.warning(f"[InputFilter] Blocked repetition flood: {text[:40]}...")
            return False, "Repetition flooding detected. Input blocked."

        # --- Layer 4: Raw Escape Sequence Injection ---
        # Catches literal \u0057 or \x57 typed as text (not actual unicode).
        # These are used to smuggle characters past keyword filters.
        if _RAW_ESCAPE_PATTERN.search(text):
            logger.warning("[InputFilter] Blocked raw unicode/hex escape injection.")
            return False, "Raw escape sequence injection detected."

        # --- Layer 5: LLM Structural Token Injection ---
        # Catches ChatML tokens (<|im_start|>), LLaMA tokens ([INST]),
        # and system tokens (<<SYS>>) used to hijack the model's context.
        if _LLM_TOKEN_PATTERN.search(text):
            logger.warning("[InputFilter] Blocked LLM structural token injection.")
            return False, "LLM structural token injection detected."

        # --- Layer 5.5: Persona Hijack / Jailbreak Detection ---
        if _PERSONA_HIJACK_PATTERN.search(text):
            logger.warning(f"[InputFilter] Blocked persona hijack/jailbreak: {text[:50]}...")
            return False, "Persona hijack / jailbreak pattern detected."

        # --- Layer 6: Keyword Injection Detection ---
        upper_text = text.upper()

        # Layer 6a: High-confidence single-match keywords
        # These patterns are almost never benign — 1 hit is enough.
        _HIGH_CONFIDENCE = [
            "IGNORE PREVIOUS", "IGNORE ALL INSTRUCTIONS",
            "DISREGARD ALL INSTRUCTIONS", "FORGET ALL INSTRUCTIONS",
            "OVERRIDE SYSTEM PROMPT", "NEW SYSTEM PROMPT",
        ]
        for hc in _HIGH_CONFIDENCE:
            if hc in upper_text:
                logger.warning(f"[InputFilter] Blocked high-confidence injection keyword: {text[:50]}...")
                return False, "Prompt injection detected (high-confidence keyword)."

        # Layer 6b: Require 2+ distinct bad-signal matches to block.
        # A single trigger word can appear in legitimate text (e.g. "override CSS"),
        # but real attacks always contain multiple injection phrases.
        hit_count = sum(1 for bad in self.bad_signals if bad in upper_text)
        if hit_count >= 2:
            logger.warning(f"[InputFilter] Blocked prompt injection keyword: {text[:50]}...")
            return False, "Prompt injection detected."

        # --- Layer 6.5: Word-Level Co-occurrence ---
        # Defeats word-insertion bypass ("DISABLE ALL SAFETY" dodges
        # "DISABLE SAFETY" but both danger words are still present).
        words_in_text = set(upper_text.split())
        # Strip punctuation from words for matching
        words_clean = {w.strip('.,;:!?\'"()[]{}') for w in words_in_text}
        action_hits = words_clean & _DANGER_ACTIONS
        target_hits = words_clean & _DANGER_TARGETS
        if action_hits and target_hits:
            logger.warning(f"[InputFilter] Blocked co-occurrence: actions={action_hits} targets={target_hits} in: {text[:50]}...")
            return False, "Prompt injection detected (action+target co-occurrence)."

        # --- Layer 6.7: Multi-Decode Expansion ---
        # Run multiple decodings of the input through the same keyword check.
        # Catches ROT13, reversed, leet speak, whitespace-smuggled, and pig latin.
        for variant in self._multi_decode(text):
            variant_upper = variant.upper()
            variant_hits = sum(1 for bad in self.bad_signals if bad in variant_upper)
            if variant_hits >= 2:
                logger.warning(f"[InputFilter] Blocked encoded injection (multi-decode): {text[:50]}...")
                return False, "Encoded prompt injection detected (multi-decode)."
            # Also check co-occurrence on decoded variants
            vwords = {w.strip('.,;:!?\'"()[]{}') for w in variant_upper.split()}
            if (vwords & _DANGER_ACTIONS) and (vwords & _DANGER_TARGETS):
                logger.warning(f"[InputFilter] Blocked encoded co-occurrence (multi-decode): {text[:50]}...")
                return False, "Encoded prompt injection detected (multi-decode co-occurrence)."

        # --- Layer 7: Safe Keyword Bypass ---
        # If the input contains a whitelisted keyword (e.g. internal tool name),
        # pass through immediately.
        if any(kw in text.lower() for kw in self.safe_keywords):
            return True, text

        return True, text

    @staticmethod
    def _ascii_fold(text):
        """
        Fold non-ASCII characters to their closest ASCII equivalent.

        Handles Greek/Cyrillic homoglyphs that survive NFKC normalization
        (e.g. Greek Ι→I, Ρ→P, Cyrillic а→a, о→o, etc.).
        Characters with no ASCII equivalent are kept as-is.
        """
        # Common homoglyph mapping: Greek/Cyrillic → Latin
        _HOMOGLYPHS = {
            '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z',
            '\u0397': 'H', '\u0399': 'I', '\u039A': 'K', '\u039C': 'M',
            '\u039D': 'N', '\u039F': 'O', '\u03A1': 'P', '\u03A4': 'T',
            '\u03A5': 'Y', '\u03A7': 'X',
            '\u03B1': 'a', '\u03B5': 'e', '\u03B9': 'i', '\u03BF': 'o',
            '\u03C5': 'u',
            # Cyrillic
            '\u0410': 'A', '\u0411': 'B', '\u0412': 'V', '\u0415': 'E',
            '\u0418': 'I', '\u041A': 'K', '\u041C': 'M', '\u041D': 'H',
            '\u041E': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T',
            '\u0423': 'Y', '\u0425': 'X',
            '\u0430': 'a', '\u0435': 'e', '\u0438': 'i', '\u043E': 'o',
            '\u0440': 'p', '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
            # Ukrainian / Extended Cyrillic
            '\u0456': 'i',  # Ukrainian і (VERY common homoglyph attack)
            '\u0406': 'I',  # Ukrainian І (uppercase)
            '\u0458': 'j',  # Cyrillic ј
            '\u0455': 's',  # Cyrillic ѕ
            '\u04BB': 'h',  # Cyrillic һ
            # Latin-like IPA / modifier letters
            '\u0261': 'g',  # Latin small letter script g
        }
        return ''.join(_HOMOGLYPHS.get(c, c) for c in text)

    @staticmethod
    def _strip_invisible(text):
        """
        Remove invisible Unicode characters that attackers insert between
        letters to bypass keyword matching.

        Strips: zero-width spaces, joiners, bidi controls, BOM, soft hyphens,
        combining grapheme joiners, invisible separators, and other invisible
        formatting characters.
        """
        # Unicode categories to strip:
        #   Cf  = Format characters (ZWJ, ZWNJ, BOM, bidi marks, soft hyphen)
        #   Cc  = Control characters (NULL, BEL, etc.) EXCEPT common whitespace
        #   Mn  = Nonspacing marks only when stacked excessively (>2 per base)
        _KEEP_CONTROL = {'\n', '\r', '\t', ' '}
        result = []
        for char in text:
            cat = unicodedata.category(char)
            if cat == 'Cf':  # Invisible format characters
                continue
            if cat == 'Mn':  # Combining diacritics (defeats accent obfuscation)
                continue
            if cat == 'Cc' and char not in _KEEP_CONTROL:
                result.append(' ')  # Replace with space to preserve word boundaries
                continue
            result.append(char)
        return ''.join(result)

    @staticmethod
    def _is_repetition_flood(text):
        """
        Detect repetition flooding: the same word repeated 10+ times,
        or single-character flood (50+ identical characters).
        """
        # Single-character flood: 50+ identical chars
        if len(text) >= 50:
            unique_chars = set(text.strip())
            if len(unique_chars) <= 2:  # 1 char + maybe whitespace
                return True
        words = text.lower().split()
        if len(words) < 12:
            return False
        from collections import Counter
        counts = Counter(words)
        most_common_word, most_common_count = counts.most_common(1)[0]
        # If any single word accounts for 60%+ of all words, it's flooding
        if most_common_count >= 10 and most_common_count / len(words) > 0.6:
            return True
        return False

    @staticmethod
    def _multi_decode(text):
        """
        Generate decoded variants of the input for multi-decode checking.

        Produces up to 5 alternative decodings:
            1. ROT13 (catches encoded instructions)
            2. Reversed string (catches backwards text)
            3. Leet speak normalized (1GN0R3 → IGNORE)
            4. Whitespace stripped (I G N O R E → IGNORE)
            5. Pig Latin stripped (IGNOREWAY → IGNORE)

        Returns:
            list[str]: Decoded variants (excludes the original).
        """
        variants = []

        # 1. ROT13
        try:
            rot13 = codecs.decode(text, 'rot_13')
            if rot13 != text:
                variants.append(rot13)
        except Exception:
            pass

        # 2. Reversed
        reversed_text = text[::-1]
        if reversed_text != text:
            variants.append(reversed_text)

        # 3. Leet speak normalization
        leet_normalized = ''.join(_LEET_MAP.get(c, c) for c in text)
        if leet_normalized != text:
            variants.append(leet_normalized)

        # 4. Whitespace collapse (defeats "I G N O R E" letter-spacing smuggling)
        # Detect letter-spaced text: single chars separated by single spaces.
        # Multi-space gaps (2+) are treated as word separators.
        # "I G N O R E  P R E V I O U S" → "IGNORE PREVIOUS"
        parts = re.split(r'(\s{2,})', text)  # Split on 2+ spaces, keeping separators
        collapsed_parts = []
        any_collapsed = False
        for part in parts:
            if re.match(r'^\s+$', part):
                # Multi-space gap → becomes single space (word boundary)
                collapsed_parts.append(' ')
            else:
                # Check if this segment is letter-spaced (single chars with single spaces)
                no_spaces = re.sub(r'\s', '', part)
                if len(no_spaces) > 2 and re.match(r'^(\S\s)*\S$', part):
                    collapsed_parts.append(no_spaces)
                    any_collapsed = True
                else:
                    collapsed_parts.append(part)
        if any_collapsed:
            collapsed = ''.join(collapsed_parts).strip()
            if collapsed != text:
                variants.append(collapsed)
        # Also try full whitespace strip as fallback
        stripped = re.sub(r'\s+', '', text)
        if stripped != text and len(stripped) > 3:
            variants.append(stripped)

        # 5. Pig Latin stripped (remove -way/-ay suffixes)
        words = text.split()
        pig_decoded = []
        changed = False
        for word in words:
            lower = word.lower()
            if lower.endswith('way') and len(word) > 4:
                pig_decoded.append(word[:-3])
                changed = True
            elif lower.endswith('ay') and len(word) > 3:
                # Move last consonant cluster back to front
                core = word[:-2]
                pig_decoded.append(core[-1] + core[:-1])
                changed = True
            else:
                pig_decoded.append(word)
        if changed:
            variants.append(' '.join(pig_decoded))

        return variants

    @staticmethod
    def _is_gibberish(text):
        """
        Detect high-entropy or obfuscated text.

        Uses three heuristics on strings longer than 50 characters:
            1. Base64 signature: long string with = padding, +, / and no spaces
            2. Space ratio < 5% AND vowel ratio < 10%
            3. Space ratio < 2% AND length > 60 (extremely dense)

        Individual URL-like tokens are exempted, but the overall text is still checked.

        Args:
            text: Text to analyze.

        Returns:
            True if the text appears to be gibberish/encoded.
        """
        # Strip out URL-like tokens so they don't skew the entropy check,
        # but still check the remaining text
        import re as _re
        url_pattern = _re.compile(r'https?://\S+|www\.\S+|magnet:\S+')
        non_url_text = url_pattern.sub('', text).strip()

        # If the entire input is just a URL, allow it
        if not non_url_text:
            return False

        # Check the non-URL portion
        check_text = non_url_text
        if len(check_text) > 50:
            space_ratio = check_text.count(" ") / len(check_text)

            # Base64 signature: no spaces + ends with = or has high base64 char density
            if space_ratio < 0.02:
                b64_chars = sum(1 for c in check_text if c in '=+/0123456789')
                b64_ratio = b64_chars / len(check_text)
                if b64_ratio > 0.08 or check_text.rstrip().endswith('='):
                    return True

            # Hex-with-spaces signature: "4d61 6c69 6369 6f75 7320"
            hex_pattern = re.compile(r'^[0-9a-fA-F]{2,4}(\s[0-9a-fA-F]{2,4}){5,}$')
            if hex_pattern.match(check_text.strip()):
                return True

            # Original heuristic: low spaces + low vowels
            if space_ratio < 0.05:
                vowels = set("aeiouAEIOU")
                vowel_count = sum(1 for c in check_text if c in vowels)
                if vowel_count / len(check_text) < 0.1:
                    return True
        return False
