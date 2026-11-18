"""Secret masking so credentials never appear in stored findings, reports or AI payloads."""
from __future__ import annotations

import re

_KNOWN = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bAIza[0-9A-Za-z_\-]{35}\b|"
    r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b|\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b|\bglpat-[0-9A-Za-z_\-]{20,}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")
_NAME = (r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|private[_-]?key|"
         r"client[_-]?secret|signing[_-]?key|encryption[_-]?key|credentials?)")
_ASSIGN = re.compile(rf"""(?i)(\b[\w.\-]*{_NAME}[\w.\-]*["']?\]?\s*[:=]\s*["'`]?)([^\s"'`#,;)]{{4,}})""")
_COMPARE = re.compile(r"""(?i)(\b\w*(?:passw\w*|pwd)\w*(?:\(\))?\s*(?:===?|!=|\.equals\()\s*["'])([^"']{3,})""")
_SKIP_VALUE = re.compile(r"^(?:\$|\{|<|%|\[?REDACTED|process\.env|os\.environ|env\.|None$|null$|true$|false$|\.\.\.)", re.I)


def _tail(v: str) -> str:
    return v[:2] + "…****"


def mask_secrets(text: str) -> str:
    if not text:
        return text
    text = _PRIVATE_KEY.sub("-----[REDACTED PRIVATE KEY]-----", text)
    text = _KNOWN.sub(lambda m: m.group(0)[:4] + "…****", text)

    def repl(m: re.Match) -> str:
        v = m.group(2)
        return m.group(1) + (v if _SKIP_VALUE.match(v) or "…****" in v else _tail(v))
    text = _ASSIGN.sub(repl, text)
    text = _COMPARE.sub(repl, text)
    return text
