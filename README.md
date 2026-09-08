# redact-hook

PostToolUse hook for Claude Code that redacts secrets and PII from tool output **before Claude sees it**. Works for all tools: `Read`, `Bash`, MCP tools (`mcp__ssh-manager__*`, etc.).

## Why

Claude Code puts every tool result into the model context. One `cat .env`, one `wg show`, one MCP call over SSH, and a live key is inside a transcript that went to a third party. You cannot recall it — you can only rotate the key.

This hook sits between the tool and the model. It cuts the secret out before the model receives it, so the leak does not happen instead of being found afterwards.

It is a last line of defence, not a replacement for keeping secrets out of tool output.

## How it works

Claude Code runs the hook after every tool call. The hook receives the tool response, applies the enabled rules, and returns the cleaned version.

Every rule has a name, and every replacement says which rule fired:

```
PGPASSWORD=[REDACTED:env_secret]
Authorization: Basic [REDACTED:basic_auth]
postgresql://app:[REDACTED:conn_str]@db.local/app
```

So the model still sees what kind of value was there, and you can read off the exact name to switch off if a rule is wrong for you.

Pure regex. No network call, no model, no dependencies — one file and the standard library, about 1 ms per tool call.

## Rules

`python3 redact_output.py --list-rules` prints these with their current state.

| Rule | Cuts | Default |
|---|---|---|
| `ssh_key` | `-----BEGIN … PRIVATE KEY-----` blocks, including PGP armour | on |
| `putty_ppk` | PuTTY `Private-Lines:` body | on |
| `awg_init` | AmneziaWG `I1 = <b 0x…>` fake TLS blobs | on |
| `awg_params` | AmneziaWG `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`–`H4` | on |
| `wg_key` | 44-char base64 after `PrivateKey`/`PublicKey`/`PresharedKey`/`PeerKey` | on |
| `hash` | bcrypt, argon2, scrypt password hashes | on |
| `docker_auth` | `"auth": "…"` in `config.json` | on |
| `k8s_key_data` | kubeconfig `client-key-data`, `client-certificate-data` | on |
| `gcp_key_id` | `"private_key_id"` in a service-account JSON | on |
| `azure_storage` | `AccountKey=` in a storage connection string | on |
| `google_api_key` | `AIza…` | on |
| `stripe` | `sk_live_`, `rk_live_`, `pk_test_`, … | on |
| `digitalocean` | `dop_v1_`, `doo_v1_`, `dor_v1_` | on |
| `telegram_bot` | `123456789:AA…` bot tokens, bare or inside `api.telegram.org/bot…` | on |
| `telegram_session` | Telethon and Pyrogram session strings — a full account takeover on their own | on |
| `telegram_api_hash` | MTProto `api_hash` / `app_hash` | on |
| `slack_webhook` | `hooks.slack.com/services/…` | on |
| `discord_webhook` | `discord.com/api/webhooks/…` | on |
| `basic_auth` | `Authorization: Basic …` | on |
| `auth_header` | `X-Api-Key:`, `Auth-Token:`, `Access-Secret:` … | on |
| `cookie` | `Set-Cookie:` values named `session`, `sid`, `token`, `csrf`, `auth` | on |
| `netrc` | `password` in a `machine …` line | on |
| `cli_userpass` | `curl -u user:pass` | on |
| `cli_password` | `--password=`, `--token=`, `--api-key=` | on |
| `bip39_seed` | 12–24 word wallet seed after `mnemonic`/`seed`/`recovery phrase` | on |
| `env_secret` | `UPPER_SNAKE` names ending `_PASS`, `_PWD`, `_SECRET`, `_TOKEN`, `_KEY`, `_DSN`, `_PAT` … plus `PGPASSWORD`, `MYSQL_PWD` | on |
| `secret_word` | `passphrase=`, `credentials=` in any case | on |
| `assignment` | `password=`, `api_key=`, `client_secret=`, `access_token=` … | on |
| `prefix` | `ghp_`, `sk-`, `AKIA`, `glpat-`, `SG.`, `npm_`, `hvs.`, `Bearer `, `dckr_pat_`, `xoxb-`, `pypi-`, `whsec_` | on |
| `conn_str` | the password in any `scheme://user:pass@host` | on |
| `jwt` | `eyJ…eyJ…` | on |
| `phone` | phone numbers with a leading `+` | on |
| `card` | 13–19 digits that pass Luhn and start with 3–6 | on |
| `email` | mail addresses | **off** |
| `ssn` | US social security numbers | **off** |
| `iban` | IBAN account numbers | **off** |
| `home_path` | the user name in `/home/…` and `/Users/…` | **off** |
| `mac_addr` | MAC addresses | **off** |
| `public_ip` | IPv4 outside the private ranges | **off** |
| `phone_loose` | phone numbers with no country code | **off** |
| `entropy` | assignment values with Shannon entropy ≥ 3.5 | **off** |

The rules are tuned against false positives, and the self-check enforces it: `re.compile(...)`, `PASSWORD = os.environ.get('X')`, `PUBLIC_KEY=ssh-ed25519`, `${GITHUB_TOKEN}`, git SHAs, UUIDs, `sha256:` digests and Go `h1:` hashes all come back byte-identical.

The seven off-by-default rules are off because cutting mail addresses, home paths and IPs breaks ordinary work with `git log`, stack traces and `ip addr`. Entropy is off because it misses about a third of real secrets and invents false positives; the named rules do the real work.

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

## Choosing the rules

Write `~/.claude/redact.toml`. Every field is optional.

```toml
# rules to switch off, by the name in [REDACTED:name]
disable = ["phone", "card"]

# rules to switch on
enable = ["entropy", "email", "home_path"]

# regexes that are never cut, whatever rule matched
allow = ["AKIAIOSFODNN7EXAMPLE", "example\\.com"]

# your own rules
[[rule]]
name    = "internal_ticket"
pattern = "ACME-\\d{6}"

[[rule]]
name        = "staff_id"
pattern     = "EMP-[0-9]{5}"
replacement = "[staff]"
```

A missing file is fine. Bad TOML, a bad regex or a rule with no `pattern` prints a warning on stderr and the rest keeps working — the hook never dies on a config error, because a dead hook redacts nothing.

### Environment variables

These override the file, so a project can set its own rules through the `env` block of its `.claude/settings.json` without a second config file.

| Variable | Default | Description |
|---|---|---|
| `REDACT_DISABLE` | unset | Comma-separated rule names to switch off |
| `REDACT_ENABLE` | unset | Comma-separated rule names to switch on |
| `REDACT_SKIP_TOOLS` | `WebFetch,WebSearch` | Tool names to pass through untouched |
| `REDACT_CONFIG` | `~/.claude/redact.toml` | Config file path |
| `REDACT_AGGRESSIVE` | unset | `1` is an alias for `REDACT_ENABLE=entropy` |

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

Read these before you trust the hook with anything.

- **PostToolUse cannot stop egress.** The tool has already run by the time the hook sees its output. This protects the model context, not the network. Only a PreToolUse hook can stop a tool from reaching out.
- **The local transcript keeps the raw value.** `toolUseResult` in `~/.claude/projects/**/*.jsonl` is written before redaction. The hook protects what goes to the API, not the file on your disk.
- Tool *input* is never redacted — a secret you type in a prompt, or that Claude puts in a command line, is not covered.
- `@file` mentions are expanded by the client and bypass hooks entirely.
- Hooks load at session start; changes to `settings.json` need a restart.
- MCP config injected via `system-reminder` bypasses PostToolUse; use `${VAR}` substitution in `.mcp.json` instead.
- The config file needs Python 3.11 or newer for `tomllib`. On an older interpreter the defaults run and a warning is printed.
- Unknown secret formats with no prefix and no field name are missed unless `entropy` is on.

## Testing

```bash
python3 redact_output.py --self-check
python3 redact_output.py --list-rules
```

`--self-check` runs both directions: one sample per rule that must be cut, and a list of ordinary output that must come back unchanged. It also fails if any default rule has no sample at all.

## Prior art

Rule shapes come from [gitleaks](https://github.com/gitleaks/gitleaks) and [detect-secrets](https://github.com/Yelp/detect-secrets), including the split between named regex rules and an entropy pass.

Three ideas were borrowed from other Claude Code redactors: named rules and a value allowlist from [redacted](https://github.com/svn-arv/redacted), type-preserving placeholders from [cc-redact](https://github.com/ShindouMihou/cc-redact), and the PreToolUse/PostToolUse limitation above, which [claude-code-redaction-hooks](https://github.com/l-mb/claude-code-redaction-hooks) documents clearly. [claude-code-redact](https://github.com/paroque28/claude-code-redact) takes the heavier road — a local proxy with round-trip un-redaction — if you want no coverage gaps and do not mind the dependencies.

## Licence

MIT. See `LICENSE`.
