#!/usr/bin/env python3
"""PostToolUse hook: redact secrets from tool output before Claude sees it.

Reads stdin JSON {tool_name, tool_input, tool_response},
writes {"hookSpecificOutput": {...}} to stdout.

Two layers, both regex:
  1. Known secret shapes — token prefixes, assignments, SSH keys, JWTs, WireGuard
  2. PII — phone numbers, Luhn-valid card numbers

Run `redact_output.py --self-check` to verify both directions: secrets are cut,
ordinary code is not.
"""
import json, os, re, sys

_PREFIX = re.compile(
    r'(dckr_pat_|tok_|sk-|ghp_|gho_|github_pat_|AKIA|hf_|xoxb-|xoxp-|Bearer\s+'
    r'|SG\.'           # SendGrid
    r'|npm_'           # npm
    r'|pypi-'          # PyPI
    r'|hvs\.'          # HashiCorp Vault service token
    r'|hvb\.'          # HashiCorp Vault batch token
    r'|glpat-'         # GitLab Personal Access Token
    r'|gldt-'          # GitLab Deploy Token
    r'|xapp-'          # Slack app token
    r'|key-'           # Mailgun
    r'|re_'            # Resend
    r'|whsec_'         # Stripe webhook secret
    r'|pat_v\d+\.'     # GitHub fine-grained PAT
    r')'
    r'([A-Za-z0-9_\-\.]{8,})',
    re.IGNORECASE,
)

# AmneziaWG fake init-packet blobs: I1 = <b 0x...hex...>
_AWG_INIT = re.compile(r'<b\s+0x[a-fA-F0-9]{20,}>')

# AmneziaWG obfuscation params — reveal handshake fingerprint
_AWG_PARAMS = re.compile(
    r'^(Jc|Jmin|Jmax|S1|S2|H1|H2|H3|H4)(\s*=\s*)\d+',
    re.MULTILINE,
)

# Docker registry auth blob in config.json
_DOCKER_AUTH = re.compile(r'("auth"\s*:\s*")[A-Za-z0-9+/]{20,}={0,2}(")')

# Separator must be a real = or : on the same line. A bare space used to join a
# keyword to whatever followed it on the next line.
_ASSIGNMENT = re.compile(
    r'(?<![A-Za-z])'
    r'(password|passwd|secret|api_key|apikey|access_key|private_key|privatekey'
    r'|presharedkey|auth_key|auth_token|access_token|client_secret|token|psk|bearer)'
    r'[ \t]*[:=][ \t]*'
    r'["\']?([A-Za-z0-9._\-/+]{6,})["\']?(?!\s*\()',
    re.IGNORECASE,
)

# WireGuard / NaCl base64 keys. Anchored to the field name: a bare 44-char
# base64 run is any base64, not a key.
_WG_KEY = re.compile(
    r'((?:Private|Public|Preshared|Peer)Key\s*=\s*)[A-Za-z0-9+/]{43}=',
    re.IGNORECASE,
)

# bcrypt / argon2 / scrypt hashes — offline-crackable, treat as secrets
_HASH = re.compile(r'\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}|\$argon2\S+|\$scrypt\S+')

# ponytail: DOTALL needed — private keys span multiple lines
_SSH_KEY = re.compile(
    r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'
    r'.*?'
    r'-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----',
    re.DOTALL,
)

_CONN_STR = re.compile(
    r'(postgresql|mysql|mongodb|redis|amqp|jdbc:\w+)://[^\s@/]+:[^\s@/]+@',
    re.IGNORECASE,
)

_JWT = re.compile(
    r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'
)

# PII. Phones need the + so version strings and ids are left alone; cards are
# checked by Luhn and by issuer digit, which rules out unix timestamps.
_PHONE = re.compile(r'(?<![\d+])\+\d[\d\s().\-]{7,17}\d(?!\d)')
_CARD = re.compile(r'(?<![\d.])([3-6](?:[ -]?\d){12,18})(?![\d.])')

# aggressive — off by default; catches unknown-format secrets but may over-redact git SHAs etc.
_LONG_HEX = re.compile(r'\b[a-fA-F0-9]{32,}\b')
_LONG_OPAQUE = re.compile(r'[A-Za-z0-9_\-]{40,}')


def _random_enough(value: str) -> bool:
    """A secret is long or has digits. `re.compile` and `npm_check.py` are neither."""
    return len(value) >= 16 or any(c.isdigit() for c in value)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _redact_card(match: re.Match) -> str:
    digits = re.sub(r'[ -]', '', match.group(1))
    if 13 <= len(digits) <= 19 and _luhn_ok(digits):
        return '[REDACTED-CARD]'
    return match.group(0)


def redact_regex(text: str, aggressive: bool = False) -> str:
    text = _SSH_KEY.sub('[REDACTED-SSH-KEY]', text)
    text = _AWG_INIT.sub('[REDACTED-AWG-INIT]', text)
    text = _AWG_PARAMS.sub(r'\1\2[REDACTED]', text)
    text = _WG_KEY.sub(r'\1[REDACTED-KEY]', text)
    text = _HASH.sub('[REDACTED-HASH]', text)
    text = _DOCKER_AUTH.sub(r'\1[REDACTED]\2', text)
    # ponytail: assignment before prefix — avoids double-[REDACTED] when both match same value
    text = _ASSIGNMENT.sub(
        lambda m: f'{m.group(1)}=[REDACTED]' if _random_enough(m.group(2)) else m.group(0),
        text,
    )
    text = _PREFIX.sub(
        lambda m: m.group(1) + '[REDACTED]' if _random_enough(m.group(2)) else m.group(0),
        text,
    )
    text = _CONN_STR.sub(lambda m: m.group(1) + '://[REDACTED]@', text)
    text = _JWT.sub('[REDACTED-JWT]', text)
    text = _PHONE.sub('[REDACTED-PHONE]', text)
    text = _CARD.sub(_redact_card, text)
    if aggressive:
        text = _LONG_HEX.sub('[REDACTED-HEX]', text)
        text = _LONG_OPAQUE.sub('[REDACTED-OPAQUE]', text)
    return text


def build_updated_response(data: dict, redacted: str) -> object:
    """Reconstruct tool_response with redacted content. CC validates against tool outputSchema."""
    resp = data.get("tool_response")
    if isinstance(resp, dict):
        # Read tool: {"type": "text", "file": {"content": "...", ...}}
        if "file" in resp and isinstance(resp["file"], dict):
            import copy
            updated = copy.deepcopy(resp)
            updated["file"]["content"] = redacted
            lines = redacted.splitlines()
            updated["file"]["numLines"] = len(lines) + 1
            updated["file"]["totalLines"] = len(lines) + 1
            return updated
        # Bash tool: {"stdout": "...", "stderr": "...", ...}
        if "stdout" in resp:
            import copy
            updated = copy.deepcopy(resp)
            updated["stdout"] = redacted
            return updated
    # fallback: plain string (MCP tools, older CC versions)
    return redacted


_SKIP_TOOLS = frozenset(os.environ.get("REDACT_SKIP_TOOLS", "WebFetch,WebSearch").split(","))

_MUST_CUT = [
    "ghp_AbCdEf0123456789ghijklmnopqrstuvwxyz",
    "password = h4nter2xyz",
    "PresharedKey = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPq=",
    "postgresql://user:s3cret@db.local/app",
    "call +7 999 123-45-67 now",
    "card 4111 1111 1111 1111 on file",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
]

_MUST_KEEP = [
    "_DOCKER_AUTH = re.compile(r'x')",
    "checks/npm_check.py",
    "systemd-ask-password --echo",
    "except: pass\nprint(count)",
    "aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQgcGFkZGluZ3M=",
    "PASSWORD = os.environ.get('X')",
    "ts 1757000000000 ms",
]


def self_check() -> int:
    bad = []
    for sample in _MUST_CUT:
        if "REDACTED" not in redact_regex(sample):
            bad.append(f"not cut: {sample!r}")
    for sample in _MUST_KEEP:
        out = redact_regex(sample)
        if out != sample:
            bad.append(f"mangled: {sample!r} -> {out!r}")
    for line in bad:
        print(line)
    print(f"{len(_MUST_CUT)} secrets, {len(_MUST_KEEP)} clean samples, {len(bad)} failures")
    return 1 if bad else 0


def main() -> None:
    data = json.load(sys.stdin)
    resp = data.get("tool_response", "")
    if data.get("tool_name") in _SKIP_TOOLS:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": resp}}))
        return
    aggressive = bool(os.environ.get("REDACT_AGGRESSIVE"))

    if isinstance(resp, dict):
        if "file" in resp and isinstance(resp.get("file"), dict):
            raw = resp["file"].get("content", "")
        elif "stdout" in resp:
            raw = resp.get("stdout", "")
        else:
            raw = json.dumps(resp)
    else:
        raw = str(resp)
    redacted = redact_regex(raw, aggressive=aggressive)
    updated = build_updated_response(data, redacted)
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": updated}}))


if __name__ == "__main__":
    if "--self-check" in sys.argv:
        sys.exit(self_check())
    main()
