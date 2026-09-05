# redact-hook

PostToolUse hook for Claude Code that redacts secrets and PII from tool output **before Claude sees it**. Works for all tools: `Read`, `Bash`, MCP tools (`mcp__ssh-manager__*`, etc.).

## Why

Claude Code puts every tool result into the model context. One `cat .env`, one `wg show`, one MCP call over SSH, and a live key is inside a transcript that went to a third party. You cannot recall it — you can only rotate the key.

This hook sits between the tool and the model. It cuts the secret out before the model receives it, so the leak does not happen instead of being found afterwards.

It is a last line of defence, not a replacement for keeping secrets out of tool output.

## How it works

Claude Code runs the hook after every tool call. The hook receives the tool response, redacts secrets, and returns the cleaned version — Claude only sees `[REDACTED]` where secrets were.

Two regex layers, both always active (~1 ms):

1. **Known secret shapes** — token prefixes, assignments, SSH keys, JWTs, WireGuard keys
2. **PII** — phone numbers and Luhn-valid card numbers

Both layers are tuned against false positives. `re.compile(...)` and `PASSWORD = os.environ.get('X')` are left alone: a redacted value must be long or contain digits, and an assignment must use a real `=` or `:`.

## What gets redacted

| Pattern | Examples |
|---|---|
| API key prefixes | `ghp_`, `sk-`, `AKIA`, `glpat-`, `SG.`, `npm_`, `hvs.`, `Bearer `, `dckr_pat_`, `xoxb-`, `pypi-`, `whsec_` |
| Assignments | `password=`, `secret=`, `api_key=`, `token=`, `private_key=`, `presharedkey=`, `client_secret=` |
| WireGuard / AmneziaWG keys | 44-char base64 after `PrivateKey`, `PublicKey`, `PresharedKey`, `PeerKey` |
| AmneziaWG obfuscation params | `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`–`H4` values |
| AmneziaWG init packets | `I1 = <b 0x...>` fake TLS blobs |
| SSH / PEM private keys | `-----BEGIN * PRIVATE KEY-----` blocks |
| Password hashes | bcrypt `$2a$`, argon2, scrypt |
| Connection strings | `postgresql://user:pass@` → `postgresql://[REDACTED]@` |
| JWTs | `eyJ...eyJ...` |
| Docker auth | `"auth": "base64blob"` in config.json |
| Phone numbers | `+7 999 123-45-67` — the leading `+` is required |
| Card numbers | 13–19 digits that pass Luhn and start with 3–6 |

Not redacted: names, emails, usernames, file paths, hostnames, IPs, PIDs, port numbers, technical identifiers, bare base64, unix timestamps.

## Installation

### 1. Copy the hook

```bash
mkdir -p ~/.claude/hooks
cp redact_output.py ~/.claude/hooks/redact_output.py
chmod +x ~/.claude/hooks/redact_output.py
```

### 2. Add to settings.json

Edit `~/.claude/settings.json` and add to the `hooks` section:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "/home/YOUR_USER/.claude/hooks/redact_output.py",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

### 3. Restart Claude Code

Hooks are loaded at session start.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `REDACT_AGGRESSIVE` | unset | `1` = also redact 32+ char hex strings and 40+ char opaque strings (may over-redact git SHAs) |
| `REDACT_SKIP_TOOLS` | `WebFetch,WebSearch` | Comma-separated tool names to skip entirely (e.g. screenshot tools) |

## Plugin installation (Claude Code skill)

This directory contains a `.claude-plugin/` with an `install-redact-hook` skill. To load it in Claude Code, add to `~/.claude/settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "redact-hook": {
      "source": {
        "source": "directory",
        "path": "/path/to/this/directory"
      }
    }
  }
}
```

Then install the plugin via `/install-plugin` in Claude Code and invoke with `/install-redact-hook`.

## Limitations

- Hooks only intercept `tool_response` — secrets typed directly in user prompts are not covered
- Hook loads at session start; changes to `settings.json` require a restart
- MCP config injected via `system-reminder` bypasses PostToolUse; use `${VAR}` substitution in `.mcp.json` instead
- Unknown secret formats with no prefix and no field name are missed unless `REDACT_AGGRESSIVE=1`

## Testing

```bash
python3 redact_output.py --self-check
```

Checks both directions: every secret sample is cut, every clean code sample is left byte-identical.

## Licence

MIT. See `LICENSE`.
