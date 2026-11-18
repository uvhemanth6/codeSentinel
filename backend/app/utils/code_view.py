"""Comment/string-aware text views.

`code_views` returns two same-length strings (newlines preserved so line numbers match):
  * nocomment: comments blanked, strings intact  (for rules that inspect literals)
  * blanked:   comments *and* string contents blanked (for structural rules)
plus the list of comments as (line, text).
"""
from __future__ import annotations

import re


def _blank(s: str) -> str:
    return re.sub(r"[^\n]", " ", s)


def code_views(text: str, style: str, python: bool = False) -> tuple[str, str, list[tuple[int, str]]]:
    if style == "none" or not text:
        return text, text, []
    n = len(text)
    nc: list[str] = []   # no-comment view
    bl: list[str] = []   # blanked view
    comments: list[tuple[int, str]] = []
    i = 0
    line = 1
    line_comment = {"c": "//", "hash": "#", "sql": "--"}.get(style)
    block = {"c": ("/*", "*/"), "sql": ("/*", "*/"), "css": ("/*", "*/"), "html": ("<!--", "-->")}.get(style)
    quotes = "\"'" if style in ("c", "hash", "sql") else ""
    if style == "c":
        quotes = "\"'`"

    def emit(raw: str, keep_nc: bool, keep_bl: bool) -> None:
        nc.append(raw if keep_nc else _blank(raw))
        bl.append(raw if keep_bl else _blank(raw))

    while i < n:
        ch = text[i]
        # block comment
        if block and text.startswith(block[0], i):
            end = text.find(block[1], i + len(block[0]))
            end = n if end == -1 else end + len(block[1])
            chunk = text[i:end]
            comments.append((line, chunk))
            emit(chunk, False, False)
            line += chunk.count("\n")
            i = end
            continue
        # line comment
        if line_comment and text.startswith(line_comment, i):
            if style == "hash" and not python and i > 0 and text[i - 1] not in " \t\n":
                pass  # e.g. URL fragment / shell var like $#; treat as normal char
            else:
                end = text.find("\n", i)
                end = n if end == -1 else end
                comments.append((line, text[i:end]))
                emit(text[i:end], False, False)
                i = end
                continue
        # python triple-quoted strings
        if python and text.startswith(('"""', "'''"), i):
            q = text[i:i + 3]
            end = text.find(q, i + 3)
            end = n if end == -1 else end + 3
            chunk = text[i:end]
            # keep delimiters in blanked view, blank the content
            emit(chunk, True, False)
            bl[-1] = q + _blank(chunk[3:-3] if len(chunk) >= 6 else "") + (q if len(chunk) >= 6 else "")
            line += chunk.count("\n")
            i = end
            continue
        # strings
        if ch in quotes:
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == ch:
                    j += 1
                    break
                if text[j] == "\n" and ch != "`":
                    break  # unterminated single-line string: stop at EOL
                j += 1
            j = min(j, n)
            chunk = text[i:j]
            emit(chunk, True, False)
            if len(chunk) >= 2 and chunk[-1] == ch:
                bl[-1] = ch + _blank(chunk[1:-1]) + ch
            else:
                bl[-1] = _blank(chunk)
            line += chunk.count("\n")
            i = j
            continue
        emit(ch, True, True)
        if ch == "\n":
            line += 1
        i += 1
    return "".join(nc), "".join(bl), comments
