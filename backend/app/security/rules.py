"""Declarative security rule catalogue (regex/line based, comment- and string-aware).

Python-specific data-flow-ish checks live in `analyzers/python_ast_security.py`; Bandit and Semgrep
are integrated separately. Every rule documents explanation, impact and remediation so each
finding is actionable on its own.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Callable, Optional, Pattern

from ..models.finding import V_POTENTIAL, V_STATIC

PY = ("Python",)
JAVA = ("Java",)
JS = ("JavaScript", "TypeScript")
CODE = ("Python", "Java", "JavaScript", "TypeScript", "Go", "Rust", "PHP", "Ruby", "C#", "Kotlin", "Shell")
WEBCODE = ("Python", "Java", "JavaScript", "TypeScript", "HTML")


@dataclass
class Rule:
    id: str
    title: str
    family: str
    severity: str
    confidence: str
    verification: str
    langs: Optional[tuple]
    pattern: Pattern
    explanation: str
    impact: str
    remediation: str
    cwe: str = ""
    sub: str = "Injection"
    view: str = "text"            # text (comments removed) | blanked (also strings blanked)
    check: Optional[Callable] = None   # (match, lines, idx, sf) -> bool | dict(overrides)
    file_requires: Optional[Pattern] = None
    file_excludes: Optional[Pattern] = None
    skip_tests: bool = True


def _c(p: str, flags: int = 0) -> Pattern:
    return re.compile(p, flags)


def _near(lines: list[str], idx: int, words: str, span: int = 2) -> bool:
    lo, hi = max(0, idx - span), min(len(lines), idx + span + 1)
    return bool(re.search(words, "\n".join(lines[lo:hi]), re.I))


PLACEHOLDER = re.compile(
    r"(?i)^(?:your|my|<|\{|\$|%|@|changeme|change_me|change-me|xxx|\*{3}|example|placeholder|dummy|sample|todo|"
    r"redacted|none$|null$|undefined$|replace|insert|enter|fake|test_?key|abc123$|process\.env|os\.environ|env\.|"
    r"getenv|\.\.\.)")
WEAK_DEFAULTS = {"admin", "password", "password1", "password123", "123456", "12345678", "root", "admin123",
                 "letmein", "qwerty", "default", "secret", "changeit", "toor"}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def _check_generic_secret(m, lines, idx, sf):
    name, value = m.group(1).lower(), m.group(2)
    if PLACEHOLDER.match(value) or "${" in value or "{{" in value or value.startswith(("http://", "https://")):
        return False
    if re.fullmatch(r"[A-Z][a-z]+(?: [A-Za-z]+)*", value) and sf.lang_name in ("JSON", "YAML", "HTML"):
        return False  # i18n label such as "Password"
    if re.search(r"(?i)(password|passwd|pwd)", name):
        weak = value.lower() in WEAK_DEFAULTS
        if value.lower() == name or (value.lower() in ("password", "secret") and not weak):
            return False
        return {"severity": "high", "title": "Hardcoded password", "confidence": "high" if len(value) >= 8 or weak
                else "medium"}
    # token / key style: require some randomness to avoid flagging words
    if len(value) >= 16 or _entropy(value) >= 3.2 and re.search(r"\d", value):
        return {"severity": "high", "title": "Hardcoded API key / secret", "confidence": "high"
                if _entropy(value) >= 3.5 else "medium"}
    return False


def _check_md5sha1(m, lines, idx, sf):
    if _near(lines, idx, r"password|passwd|pwd|secret|credential", 3):
        return {"severity": "high", "confidence": "high", "title": "Weak hash (MD5/SHA-1) used for credentials"}
    return {"severity": "medium", "confidence": "medium"}


def _check_insecure_random(m, lines, idx, sf):
    return _near(lines, idx, r"token|password|passwd|secret|session|otp|nonce|csrf|api_?key|salt|reset", 2)


def _check_http_url(m, lines, idx, sf):
    url = m.group(0)
    if re.search(r"(?i)http://(?:localhost|127\.|0\.0\.0\.0|\[::1\]|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|"
                 r"[\w.-]*\.(?:local|localhost|internal|test|example)\b|[\w.-]*example\.(?:com|org|net)|"
                 r"www\.w3\.org|schemas\.|java\.sun\.com|xmlns|maven\.apache\.org|json-schema\.org|"
                 r"[\w.-]*\.xsd|purl\.org|ns\.adobe\.com|\$\{|\{\{)", url):
        return False
    if _near(lines, idx, r"xmlns|DOCTYPE|namespace|@see|license", 0):
        return False
    if _near(lines, idx, r"login|auth|token|password|api|payment|checkout|oauth", 1):
        return {"severity": "medium", "confidence": "high"}
    return True


def _check_innerhtml(m, lines, idx, sf):
    rhs = lines[idx][m.end():].strip()
    return not re.fullmatch(r"""(?:["'`][^"'`$+]*["'`]|\s*);?""", rhs)  # plain literal assignment is safe


def _check_nonliteral_arg(m, lines, idx, sf):
    """True when the first argument after the matched `name(` is not a plain string literal."""
    rest = lines[idx][m.end():].lstrip()
    return not re.match(r"""(["'])[^"'\\]*\1\s*\)""", rest)


def _check_not_compare_empty(m, lines, idx, sf):
    t = m.group(0).lower()
    if re.search(r"(?:==|!=)\s*(?:none|null|undefined|\"\s*\"|'\s*'|``)\s*$", t) or "hash" in t or "digest" in t:
        return False
    if re.search(r"(?:==|!=)\s*(?:len|\d)", t):
        return False
    return True


_DOCTYPE_SAFE = _c(r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD|setFeature\(|"
                   r"IS_SUPPORTING_EXTERNAL_ENTITIES|setExpandEntityReferences\(\s*false")

RULES: list[Rule] = [
    # ---------------------------------------------------------------- secrets
    Rule("SEC-SECRET-AWS", "Hardcoded AWS access key ID", "hardcoded-secret", "critical", "high", V_STATIC, None,
         _c(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
         "A string matching the AWS access key ID format is committed in source code.",
         "Anyone with repository access (or a leaked copy) can authenticate to AWS as this identity.",
         "Revoke and rotate the key, remove it from history, and load credentials from the environment or a "
         "secrets manager (e.g. AWS IAM roles).", "CWE-798", "Secrets"),
    Rule("SEC-SECRET-PRIVKEY", "Private key committed to repository", "hardcoded-secret", "critical", "high",
         V_STATIC, None, _c(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
         "A PEM private key block is present in the source tree.",
         "The key can be used to impersonate the service, decrypt traffic or sign malicious artifacts.",
         "Remove the key, rotate/revoke it, and store key material in a secrets manager or mounted secret.",
         "CWE-321", "Secrets"),
    Rule("SEC-SECRET-TOKEN", "Hardcoded service token", "hardcoded-secret", "critical", "high", V_STATIC, None,
         _c(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|AIza[0-9A-Za-z_\-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|"
            r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}|glpat-[0-9A-Za-z_\-]{20,}|SG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,})\b"),
         "A string matching a well-known provider token format (GitHub, Google, Slack, Stripe, GitLab, SendGrid) "
         "is present in code.",
         "A leaked token grants direct access to the provider account or API with the token's privileges.",
         "Revoke the token immediately, purge it from git history, and inject it via environment variables or a "
         "secrets manager.", "CWE-798", "Secrets"),
    Rule("SEC-SECRET-GENERIC", "Hardcoded credential", "hardcoded-secret", "high", "medium", V_POTENTIAL, None,
         _c(r"""(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret[_-]?key|secret|api[_-]?key|apikey|access[_-]?token|"""
            r"""auth[_-]?token|private[_-]?key|client[_-]?secret|jwt[_-]?secret|signing[_-]?key|encryption[_-]?key|"""
            r"""db[_-]?pass))\b["']?\]?\s*[:=]\s*["'`]([^"'`\s]{6,})["'`]"""),
         "A credential-like variable is assigned a literal value in source code.",
         "Secrets in source control are exposed to everyone with read access and persist in git history.",
         "Move the value to an environment variable or secrets manager, rotate it, and fail fast at startup if it "
         "is not configured.", "CWE-798", "Secrets", check=_check_generic_secret),
    Rule("SEC-SECRET-CONFIG", "Credential stored in configuration file", "hardcoded-secret", "high", "medium",
         V_POTENTIAL, ("Properties", "YAML"),
         _c(r"""(?i)^\s*([\w.\-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|"""
            r"""client[_-]?secret|signing[_-]?key))\s*[:=]\s*["']?([^\s#"'$][^\s#"']{5,})["']?\s*$"""),
         "A configuration file contains a literal credential value.",
         "Credentials in committed configuration are exposed to everyone with repository access.",
         "Use environment placeholders (e.g. ${DB_PASSWORD}) or a secrets manager, and rotate the exposed value.",
         "CWE-798", "Secrets", check=_check_generic_secret, skip_tests=False),
    # ---------------------------------------------------------------- injection
    Rule("SEC-SQLI-CONCAT", "SQL query built with string concatenation/formatting", "sql-injection", "high",
         "medium", V_POTENTIAL, ("Python", "Java", "JavaScript", "TypeScript", "Go", "PHP", "Ruby", "C#", "Kotlin"),
         _c(r"""(?i)["'`]\s*(?:SELECT\b[^"'`]*\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM\s+\w+)\b[^\n]*?"""
            r"""["'`]\s*(?:\+\s*[\w(]|%\s*[\w(]|\.format\()"""),
         "A SQL statement is assembled by concatenating or formatting values into the query text.",
         "If any interpolated value is attacker-controlled, the query can be altered (data theft, auth bypass, "
         "data destruction).",
         "Use parameterised queries / prepared statements (placeholders) and never build SQL from user input.",
         "CWE-89", "Injection"),
    Rule("SEC-SQLI-FSTRING", "SQL query built with f-string / template literal", "sql-injection", "high", "medium",
         V_POTENTIAL, ("Python", "JavaScript", "TypeScript"),
         _c(r"""(?i)(?:\bf["']\s*(?:SELECT\b[^"']*\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^"'\n]*\{"""
            r"""|`\s*(?:SELECT\b[^`]*\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^`]*\$\{)"""),
         "A SQL statement is built using string interpolation.",
         "Interpolated values reach the database as SQL syntax, enabling SQL injection.",
         "Replace interpolation with bound parameters (e.g. `cursor.execute(sql, params)` / `?` placeholders).",
         "CWE-89", "Injection"),
    Rule("SEC-SQLI-JAVA-EXEC", "Dynamic SQL passed to JDBC/JPA call", "sql-injection", "high", "medium",
         V_POTENTIAL, JAVA,
         _c(r"""\.(?:executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|"""
            r"""queryForList|queryForObject|queryForMap)\s*\(\s*(?:"[^"]*"\s*\+|[A-Za-z_]\w*\s*\+|String\.format\()"""),
         "A JDBC/JPA/Spring JDBC call receives a query that is concatenated or formatted at runtime.",
         "User-controlled data in the query string allows SQL injection.",
         "Use PreparedStatement with `?` parameters or named parameters in JPA/Spring JDBC.", "CWE-89", "Injection"),
    Rule("SEC-CMDI-JS", "Shell command built from dynamic input", "command-injection", "high", "medium",
         V_POTENTIAL, JS,
         _c(r"""\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"'\n]*["']\s*\+|[A-Za-z_][\w.]*\s*[,)])"""),
         "`child_process.exec*` is called with a command string that contains dynamic data.",
         "The command runs in a shell, so metacharacters in the dynamic part allow arbitrary command execution.",
         "Use `execFile`/`spawn` with an argument array and no shell, and validate inputs against an allow-list.",
         "CWE-78", "Injection", file_requires=_c(r"child_process")),
    Rule("SEC-CMDI-JAVA", "OS command built from dynamic input", "command-injection", "high", "medium",
         V_POTENTIAL, JAVA,
         _c(r"""Runtime\.getRuntime\(\)\s*\.exec\(\s*(?:"[^"]*"\s*\+|[A-Za-z_]\w*\s*[+)])|"-c"\s*,\s*[A-Za-z_]\w*"""),
         "A command string is assembled at runtime and passed to the operating system.",
         "Attacker-controlled fragments can execute arbitrary commands with the application's privileges.",
         "Pass arguments as a fixed array to ProcessBuilder, avoid `sh -c`, and validate against an allow-list.",
         "CWE-78", "Injection"),
    Rule("SEC-SSRF", "Outbound request URL taken from user input", "ssrf", "medium", "medium", V_POTENTIAL, None,
         _c(r"""(?:requests\.(?:get|post|put|delete|head|request)|urlopen|httpx\.(?:get|post)|axios(?:\.\w+)?|fetch|got|"""
            r"""http\.get|https\.get)\s*\(\s*(?:request|req)\.(?:args|form|values|json|query|body|params|GET|POST)"""),
         "The target URL of a server-side HTTP request comes directly from request data.",
         "Attackers can make the server call internal services or cloud metadata endpoints (SSRF).",
         "Validate the URL against an allow-list of hosts/schemes and block private address ranges.",
         "CWE-918", "Injection", view="blanked"),
    Rule("SEC-REDIRECT", "Open redirect from request parameter", "open-redirect", "medium", "medium", V_POTENTIAL, None,
         _c(r"""(?:\bredirect\(|res\.redirect\(|sendRedirect\()\s*(?:request|req)\.(?:args|form|values|query|body|"""
            r"""params|GET|POST|getParameter)"""),
         "A redirect target is taken from user-controlled input without validation.",
         "Attackers can craft links on your domain that send victims to phishing sites.",
         "Only redirect to relative paths or an allow-list of known destinations.", "CWE-601", "Injection",
         view="blanked"),
    # ---------------------------------------------------------------- deserialization
    Rule("SEC-DESER-PY", "Unsafe deserialization (pickle/marshal/dill)", "unsafe-deserialization", "high", "high",
         V_STATIC, PY, _c(r"\b(?:c?[Pp]ickle|dill|marshal|jsonpickle)\.(?:loads?|decode)\s*\("),
         "Data is deserialized with a format that can execute arbitrary code during loading.",
         "If the data is attacker-influenced this gives remote code execution.",
         "Use a safe data format (JSON) or sign and verify the payload before deserializing.", "CWE-502",
         "Deserialization", view="blanked"),
    Rule("SEC-DESER-YAML", "yaml.load without a safe loader", "unsafe-deserialization", "high", "high", V_STATIC,
         PY, _c(r"\byaml\.(?:load|load_all|unsafe_load)\s*\((?![^)\n]*Safe)"),
         "`yaml.load` with the default/unsafe loader can construct arbitrary Python objects.",
         "A crafted YAML document can execute code on load.", "Use `yaml.safe_load` (or `Loader=yaml.SafeLoader`).",
         "CWE-502", "Deserialization", view="blanked"),
    Rule("SEC-DESER-JAVA", "Unsafe Java deserialization", "unsafe-deserialization", "high", "medium", V_POTENTIAL,
         JAVA, _c(r"new\s+ObjectInputStream\s*\(|\bXMLDecoder\s*\(|enableDefaultTyping\s*\(|new\s+Yaml\(\s*\)\s*\.load"),
         "Native Java deserialization (or polymorphic JSON/YAML typing) of external data is used.",
         "Gadget chains in the classpath can turn crafted input into remote code execution.",
         "Avoid native serialization for untrusted data; use JSON with fixed types, or add a deserialization "
         "filter (ObjectInputFilter).", "CWE-502", "Deserialization", view="blanked"),
    Rule("SEC-DESER-JS", "Unsafe deserialization library", "unsafe-deserialization", "high", "medium", V_POTENTIAL,
         JS, _c(r"""require\(\s*['"]node-serialize['"]\s*\)|\bunserialize\s*\(|\bserialize\.unserialize\s*\("""),
         "A library known for code execution on deserialization is used.",
         "Untrusted payloads can execute code inside the Node.js process.",
         "Replace with JSON.parse plus schema validation.", "CWE-502", "Deserialization"),
    # ---------------------------------------------------------------- XSS
    Rule("SEC-XSS-INNERHTML", "Unescaped HTML sink (innerHTML / outerHTML)", "xss", "medium", "medium", V_POTENTIAL,
         JS + ("HTML",), _c(r"\.(?:innerHTML|outerHTML)\s*\+?="), 
         "Content is written to the DOM as HTML rather than text.",
         "If the value includes user data, scripts can run in the victim's browser (stored/reflected XSS).",
         "Use `textContent`, or sanitise with a vetted library (e.g. DOMPurify) before assigning HTML.",
         "CWE-79", "Cross-Site Scripting", check=_check_innerhtml),
    Rule("SEC-XSS-DOCWRITE", "document.write / insertAdjacentHTML usage", "xss", "medium", "medium", V_POTENTIAL,
         JS + ("HTML",), _c(r"\bdocument\.write(?:ln)?\s*\(|\.insertAdjacentHTML\s*\("),
         "HTML is injected into the page with a parser-level API.", "User-controlled data leads to XSS.",
         "Build DOM nodes with `createElement`/`textContent` or sanitise first.", "CWE-79", "Cross-Site Scripting",
         view="blanked"),
    Rule("SEC-XSS-REACT", "dangerouslySetInnerHTML / v-html", "xss", "medium", "medium", V_POTENTIAL,
         JS + ("HTML",), _c(r"dangerouslySetInnerHTML|\bv-html\s*="),
         "The framework's HTML escaping is explicitly bypassed.", "Unsanitised content can run scripts (XSS).",
         "Sanitise with DOMPurify or render as text.", "CWE-79", "Cross-Site Scripting"),
    Rule("SEC-XSS-TEMPLATE", "Template autoescape bypass", "xss", "medium", "high", V_STATIC, PY + ("HTML",),
         _c(r"\{\{[^}\n]*\|\s*safe\s*\}\}|autoescape\s*=\s*False|\bMarkup\(|\bmark_safe\("),
         "Output escaping is disabled or content is marked as trusted HTML.",
         "Any user data flowing through reaches the browser unescaped (XSS).",
         "Remove `|safe`/`mark_safe` for user data, or sanitise it first; keep autoescape enabled.",
         "CWE-79", "Cross-Site Scripting"),
    Rule("SEC-XSS-REFLECT", "User input reflected into HTML response", "xss", "high", "medium", V_POTENTIAL, None,
         _c(r"""(?:return\s+f?["']\s*<[^\n]*(?:\{\s*(?:request|req)\.|%\s*(?:request|req)\.|\+\s*(?:request|req)\.)"""
            r"""|res\.send\(\s*(?:`[^`\n]*<[^`\n]*\$\{|["'][^"'\n]*<[^"'\n]*["']\s*\+)"""
            r"""|getWriter\(\)\s*\.\s*(?:print|println|write|append)\s*\([^;\n]*\+[^;\n]*\)"""
            r"""|render_template_string\(\s*f["'])"""),
         "A response is built as HTML by concatenating request data.",
         "Reflected cross-site scripting: crafted links execute script in victims' sessions.",
         "Escape output (`html.escape`/framework templates) or return JSON with the correct content type.",
         "CWE-79", "Cross-Site Scripting"),
    # ---------------------------------------------------------------- path traversal / files
    Rule("SEC-PATH-REQ", "File path derived from request input", "path-traversal", "high", "medium", V_POTENTIAL,
         None,
         _c(r"""(?:\bopen|send_file|send_from_directory|os\.path\.join|readFile(?:Sync)?|createReadStream|sendFile|"""
            r"""writeFile(?:Sync)?|unlink(?:Sync)?|path\.(?:join|resolve)|res\.download|new\s+File(?:InputStream|Reader|"""
            r"""OutputStream)?|Paths\.get|Files\.(?:read\w+|write)|FileSystemResource)\s*\([^\n]*"""
            r"""\b(?:request\.(?:args|form|values|json|files|data|view_args)|req\.(?:params|query|body)|getParameter\()"""),
         "A filesystem path is built from request-controlled data.",
         "`../` sequences can read or overwrite files outside the intended directory.",
         "Resolve the final path and verify it stays inside an allowed base directory; prefer opaque IDs over "
         "client-supplied file names.", "CWE-22", "File Handling", view="blanked"),
    Rule("SEC-PATH-EXTRACT", "Archive extraction without path validation", "path-traversal", "medium", "medium",
         V_POTENTIAL, PY, _c(r"\.extractall\s*\("),
         "`extractall` on a zip/tar archive trusts member names.",
         "A malicious archive can write files outside the target directory (zip-slip).",
         "Validate each member's resolved path (or use `filter='data'` for tarfile) before extracting.",
         "CWE-22", "File Handling", view="blanked",
         check=lambda m, l, i, sf: not _near(l, i, r"filter\s*=", 3)),
    Rule("SEC-FILE-PERMS", "Overly permissive file permissions", "insecure-file-ops", "medium", "high", V_STATIC,
         None, _c(r"(?i)\b(?:chmod|fchmod)\b[^\n]*\b(?:0o?777|0o?666|a\+rwx|ugo\+rwx)\b"),
         "A file or directory is made world-writable/readable.",
         "Any local user can modify or replace the file, enabling privilege escalation or tampering.",
         "Use least-privilege modes such as 0o600 (files) or 0o750 (directories).", "CWE-732", "File Handling"),
    Rule("SEC-TEMPFILE", "Insecure temporary file usage", "insecure-file-ops", "medium", "medium", V_POTENTIAL, PY,
         _c(r"\btempfile\.mktemp\s*\("),
         "`mktemp` returns a name without creating the file, which is a race condition.",
         "Attackers can pre-create or symlink the file (TOCTOU) to hijack writes.",
         "Use `tempfile.NamedTemporaryFile` or `mkstemp`.", "CWE-377", "File Handling", view="blanked"),
    # ---------------------------------------------------------------- crypto
    Rule("SEC-CRYPTO-HASH-PY", "Weak hash algorithm (MD5/SHA-1)", "weak-crypto", "medium", "medium", V_POTENTIAL, PY,
         _c(r"""\bhashlib\.(?:md5|sha1)\s*\(|hashlib\.new\(\s*["'](?:md5|sha1)["']"""),
         "MD5/SHA-1 are cryptographically broken for collision resistance and unsuitable for passwords.",
         "Hashes can be forged or cracked quickly if used for integrity, signatures or credentials.",
         "Use SHA-256+ for integrity and bcrypt/scrypt/argon2 for passwords.", "CWE-327", "Cryptography",
         check=_check_md5sha1),
    Rule("SEC-CRYPTO-HASH-JAVA", "Weak hash algorithm (MD5/SHA-1)", "weak-crypto", "medium", "medium", V_POTENTIAL,
         JAVA, _c(r"""MessageDigest\.getInstance\(\s*"(?:MD5|MD2|SHA-?1)"\s*\)"""),
         "MD5/SHA-1 are cryptographically broken.", "Hashes can be forged or cracked quickly.",
         "Use SHA-256+ for integrity and a password hashing function (BCrypt/Argon2) for credentials.",
         "CWE-327", "Cryptography", check=_check_md5sha1),
    Rule("SEC-CRYPTO-HASH-JS", "Weak hash algorithm (MD5/SHA-1)", "weak-crypto", "medium", "medium", V_POTENTIAL,
         JS, _c(r"""createHash\(\s*['"](?:md5|sha1)['"]\s*\)"""),
         "MD5/SHA-1 are cryptographically broken.", "Hashes can be forged or cracked quickly.",
         "Use SHA-256+ for integrity and bcrypt/argon2 for passwords.", "CWE-327", "Cryptography",
         check=_check_md5sha1),
    Rule("SEC-CRYPTO-CIPHER", "Weak or insecure cipher/mode", "weak-crypto", "high", "high", V_STATIC, None,
         _c(r"""Cipher\.getInstance\(\s*"(?:DES|DESede|RC4|RC2|Blowfish|AES)(?:/ECB[^"]*)?"\s*\)|"AES/ECB|"""
            r"""createCipher(?:iv)?\(\s*['"](?:des|rc4|aes-\d+-ecb)|\bMODE_ECB\b|Crypto\.Cipher\.(?:DES|ARC4)|\bNullCipher\b"""),
         "A broken cipher or ECB mode (or the JCE default of AES/ECB) is used.",
         "Ciphertext leaks patterns and can be decrypted or tampered with.",
         "Use AES-GCM (or ChaCha20-Poly1305) with a unique random nonce per message.", "CWE-327", "Cryptography"),
    Rule("SEC-CRYPTO-RANDOM", "Non-cryptographic random used for security value", "weak-crypto", "medium",
         "medium", V_POTENTIAL, None,
         _c(r"\bMath\.random\s*\(|\brandom\.(?:random|randint|choice|choices|randrange|getrandbits)\s*\(|"
            r"\bnew\s+Random\s*\("),
         "A predictable PRNG is used near code that generates tokens, passwords, sessions or secrets.",
         "Predictable values can be guessed, enabling account takeover or forged tokens.",
         "Use `secrets`/`crypto.randomBytes`/`SecureRandom`.", "CWE-338", "Cryptography", view="blanked",
         check=_check_insecure_random),
    Rule("SEC-CRYPTO-TLSVER", "Deprecated SSL/TLS protocol version", "weak-crypto", "medium", "high", V_STATIC, None,
         _c(r"""ssl\.PROTOCOL_(?:SSLv2|SSLv3|TLSv1(?:_1)?)\b|SSLContext\.getInstance\(\s*"(?:SSL|SSLv3|TLSv1(?:\.1)?)"|"""
            r"""secureProtocol\s*:\s*['"](?:SSLv3|TLSv1(?:_1)?_method)"""),
         "A deprecated protocol version is requested.", "Known attacks (POODLE, BEAST) can break the session.",
         "Require TLS 1.2 or 1.3.", "CWE-326", "Cryptography"),
    # ---------------------------------------------------------------- transport
    Rule("SEC-HTTP-URL", "Insecure HTTP URL", "insecure-http", "low", "medium", V_POTENTIAL,
         ("Python", "Java", "JavaScript", "TypeScript", "JSON", "YAML", "Properties", "Go", "PHP", "Ruby", "C#",
          "Kotlin"),
         _c(r"""http://[A-Za-z0-9][^\s"'`)<>]*"""),
         "A plain-text HTTP URL is hard-coded.", "Traffic can be read or modified in transit (MITM).",
         "Use https:// endpoints and enforce TLS (HSTS) for any non-local address.", "CWE-319", "Transport Security",
         check=_check_http_url),
    Rule("SEC-TLS-DISABLED", "TLS certificate verification disabled", "tls-verification-disabled", "high", "high",
         V_STATIC, None,
         _c(r"""\bverify\s*=\s*False\b|ssl\._create_unverified_context|\bCERT_NONE\b|check_hostname\s*=\s*False|"""
            r"""rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['"]?\s*[=:]\s*['"]?0|"""
            r"""NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllStrategy|InsecureSkipVerify\s*:\s*true|"""
            r"""setHostnameVerifier\([^)]*->\s*true"""),
         "Certificate or hostname validation is turned off.",
         "Connections can be intercepted by a man-in-the-middle without detection.",
         "Keep verification enabled; trust a private CA via a custom CA bundle if needed.", "CWE-295",
         "Transport Security", view="blanked"),
    # ---------------------------------------------------------------- data exposure
    Rule("SEC-LOG-SECRET", "Sensitive value written to logs/console", "sensitive-data-exposure", "medium", "medium",
         V_POTENTIAL, CODE,
         _c(r"(?i)(?:\bprint|println|printf|console\.\w+|\blog(?:ger)?\.\w+|logging\.\w+|System\.(?:out|err)\.print\w*)"
            r"\s*\([^\n]*\b(?:password|passwd|pwd|secret|api_?key|access_?token|auth_?token|credit_?card|card_?number|"
            r"cvv|ssn)\b"),
         "A variable that looks like a credential or personal data is passed to a logging/print call.",
         "Secrets and personal data end up in log files, aggregators and terminals with broad access.",
         "Remove the value from the message or mask/redact it before logging.", "CWE-532", "Information Exposure",
         view="blanked"),
    Rule("SEC-ERR-LEAK", "Stack trace / exception details returned to client", "sensitive-data-exposure", "medium",
         "medium", V_POTENTIAL, PY + JS,
         _c(r"""(?:return|jsonify|Response|make_response|res\.(?:status\(\d+\)\.)?(?:send|json))[^\n]*"""
            r"""(?:traceback\.format_exc\(\)|\b(?:err|error)\.stack\b)"""),
         "Internal exception details are included in a client response.",
         "Stack traces reveal file paths, library versions and logic that aid attackers.",
         "Log details server-side and return a generic error message with a correlation ID.", "CWE-209",
         "Information Exposure", view="blanked"),
    Rule("SEC-DEBUG-FLASK", "Flask debug mode enabled", "debug-enabled", "high", "high", V_STATIC, PY,
         _c(r"\.run\([^)\n]*\bdebug\s*=\s*True"),
         "The Werkzeug debugger is enabled in an `app.run(debug=True)` call.",
         "The interactive debugger allows remote code execution if the app is reachable.",
         "Disable debug outside local development; drive it from an environment variable.", "CWE-489",
         "Configuration", view="blanked"),
    Rule("SEC-CORS-WILDCARD", "Permissive CORS policy", "permissive-cors", "medium", "medium", V_POTENTIAL, None,
         _c(r"""\bCORS\(\s*[A-Za-z_]\w*\s*\)|origins?\s*[=:]\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|"""
            r"""\bcors\(\s*\)|@CrossOrigin(?:\(\s*(?:origins\s*=\s*)?"\*"\s*\))?(?!\s*\()|allowedOrigins\(\s*"\*"\s*\)|"""
            r"""cors\(\s*\{\s*origin\s*:\s*true"""),
         "Cross-origin requests are allowed from any origin.",
         "Any website can call the API from a victim's browser, which is dangerous if credentials/cookies are used.",
         "Restrict origins to an explicit allow-list of trusted front-ends.", "CWE-942", "Configuration"),
    Rule("SEC-BIND-ALL", "Service binds to all network interfaces", "bind-all", "low", "medium", V_POTENTIAL, CODE,
         _c(r"""\bhost\s*=\s*["']0\.0\.0\.0["']|\.listen\([^)]*["']0\.0\.0\.0["']"""),
         "The server listens on 0.0.0.0.", "The service is reachable from every network the host is attached to.",
         "Bind to 127.0.0.1 unless external exposure is intended and protected.", "CWE-668", "Configuration"),
    # ---------------------------------------------------------------- authentication
    Rule("SEC-AUTH-JWT", "JWT verification disabled or weakened", "unsafe-authentication", "critical", "high",
         V_STATIC, None,
         _c(r"""jwt\.decode\([^)\n]*(?:verify\s*=\s*False|verify_signature["']?\s*:\s*False)|algorithms?\s*[=:]\s*\[?\s*["']none["']|"""
            r"""algorithm\s*:\s*['"]none['"]|ignoreExpiration\s*:\s*true"""),
         "Token signature/expiry checking is disabled or the `none` algorithm is accepted.",
         "Attackers can forge tokens and impersonate any user.",
         "Always verify signatures with a pinned algorithm list and validate `exp`/`aud`/`iss`.", "CWE-347",
         "Authentication"),
    Rule("SEC-AUTH-JWT-DECODE", "JWT decoded without verification", "unsafe-authentication", "medium", "low",
         V_POTENTIAL, JS, _c(r"\bjwt\.decode\s*\("),
         "`jsonwebtoken.decode` does not verify the signature.",
         "If the result is trusted for authorisation, tokens can be forged.", "Use `jwt.verify` for any trust decision.",
         "CWE-347", "Authentication", view="blanked"),
    Rule("SEC-AUTH-PLAINCMP", "Password compared as plain text", "unsafe-authentication", "high", "medium",
         V_POTENTIAL, CODE,
         _c(r"""\b\w*(?:[Pp]assword|passwd|pwd|PASSWORD)\w*(?:\(\))?\s*(?:===?|!==?)\s*[\w.\[\]()'"]+|"""
            r"""\b\w*(?:[Pp]assword|passwd)\w*(?:\(\))?\.equals\("""),
         "A password is compared directly against another value, implying plain-text storage or a timing-unsafe "
         "comparison.",
         "Plain-text password storage exposes all accounts in a breach; `==` comparisons leak timing information.",
         "Store salted password hashes (bcrypt/argon2) and verify with the library's constant-time check.",
         "CWE-256", "Authentication", view="blanked", check=_check_not_compare_empty),
    Rule("SEC-AUTH-HARDCODED-CMP", "Credential compared with a literal", "unsafe-authentication", "high", "high",
         V_STATIC, CODE,
         _c(r"""\b\w*(?:[Pp]assword|passwd|pwd)\w*(?:\(\))?(?:\s*(?:===?|!=)\s*|\.equals\(\s*)["'][^"'\s]{3,}["']|"""
            r"""["'][^"'\s]{3,}["']\s*(?:===?|!=)\s*\w*(?:[Pp]assword|passwd|pwd)\w*"""),
         "Authentication logic compares a credential with a hard-coded value.",
         "Anyone who reads the source knows the credential (backdoor).",
         "Authenticate against hashed credentials stored in a database or identity provider.", "CWE-798",
         "Authentication"),
    Rule("SEC-AUTH-SPRING", "Spring Security protections disabled", "unsafe-authentication", "high", "high",
         V_STATIC, JAVA,
         _c(r"csrf\(\)\s*\.\s*disable\(\)|csrf\(\s*\w*Configurer::disable\s*\)|anyRequest\(\)\s*\.\s*permitAll\(\)|"
            r"antMatchers\(\s*\"/\*\*\"\s*\)\s*\.\s*permitAll|NoOpPasswordEncoder|\{noop\}"),
         "CSRF protection is disabled, all requests are permitted or passwords are stored without encoding.",
         "Endpoints become unauthenticated or vulnerable to cross-site request forgery.",
         "Enable CSRF for session-based apps, require authentication by default and use BCryptPasswordEncoder.",
         "CWE-352", "Authentication"),
    Rule("SEC-COOKIE-INSECURE", "Cookie / session flags weakened", "insecure-cookie", "medium", "high", V_STATIC,
         None,
         _c(r"""(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY)\s*=\s*False|"""
            r"""\bhttpOnly\s*:\s*false|\bsecure\s*:\s*false|@csrf_exempt|ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]"""),
         "A session cookie/CSRF/host-validation safeguard is turned off.",
         "Cookies can be stolen by scripts or sent over HTTP; forged cross-site requests are accepted.",
         "Enable Secure, HttpOnly and SameSite flags, keep CSRF protection, and list explicit allowed hosts.",
         "CWE-614", "Authentication"),
    # ---------------------------------------------------------------- dangerous functions
    Rule("SEC-DANGEROUS-EVAL", "Dynamic code execution (eval/exec)", "dangerous-function", "high", "high",
         V_POTENTIAL, PY + JS,
         _c(r"(?<![\w.])(?:eval|exec)\s*\(|\bnew\s+Function\s*\(|\b(?:setTimeout|setInterval)\s*\(\s*[\"'`]|"
            r"\bvm\.(?:runIn\w+|compileFunction)\s*\("),
         "Code is evaluated from a string at runtime.",
         "If any part of the string is influenced by users, attackers can run arbitrary code.",
         "Replace with data parsing (`json.loads`, `ast.literal_eval`) or explicit dispatch tables.", "CWE-95",
         "Dangerous Functions", view="blanked",
         check=lambda m, l, i, sf: not (sf.lang_name != "Python" and m.group(0).lstrip().startswith("exec"))),
    Rule("SEC-DANGEROUS-JAVA", "Dangerous reflection/scripting API", "dangerous-function", "medium", "medium",
         V_POTENTIAL, JAVA,
         _c(r"ScriptEngine\w*\s*\.\s*eval\(|\.getEngineByName\(|Class\.forName\(\s*[A-Za-z_]\w*\s*\)|"
            r"\.setAccessible\(\s*true\s*\)"),
         "Runtime code evaluation or reflective access is used.",
         "With attacker-influenced input this allows arbitrary code execution or bypassing encapsulation.",
         "Avoid dynamic evaluation; use explicit mappings and validate class names against an allow-list.",
         "CWE-470", "Dangerous Functions", view="blanked"),
    Rule("SEC-XXE", "XML parser without XXE protection", "xxe", "high", "medium", V_POTENTIAL, JAVA,
         _c(r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)"
            r"\.newInstance\("),
         "An XML factory is created and the file never disables DOCTYPE/external entities.",
         "Crafted XML can read local files or trigger SSRF (XXE).",
         "Set `disallow-doctype-decl` / FEATURE_SECURE_PROCESSING and disable external entities.", "CWE-611",
         "Injection", view="blanked", file_excludes=_DOCTYPE_SAFE),
    Rule("SEC-PIPE-SHELL", "Remote script piped to a shell", "dangerous-function", "medium", "high", V_STATIC, None,
         _c(r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"),
         "A downloaded script is executed without verification.",
         "A compromised or intercepted download executes arbitrary code in your build/runtime environment.",
         "Download, verify a checksum/signature, then execute.", "CWE-494", "Dangerous Functions"),
]
