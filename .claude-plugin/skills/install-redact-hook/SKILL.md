---
name: install-redact-hook
description: Install the PostToolUse secret-redaction hook into this Claude Code instance. Copies redact_output.py to ~/.claude/hooks/ and wires it into settings.json. Run when the user says "install redact hook", "set up secret redaction", or "install privacy hook".
allowed-tools: Bash, Read, Edit, Write
---

# Install Redact Hook

Install the PostToolUse hook that redacts secrets and PII from all tool output before Claude sees it.

## Steps

### 1. Locate the hook script

The script `redact_output.py` must be available. Check the current directory first, then ask the user for the path if not found:

```bash
ls redact_output.py 2>/dev/null || echo "not found"
```

If not found, ask the user: "Where is redact_output.py? (or I can download it from the repo)"

### 2. Install the hook script

```bash
mkdir -p ~/.claude/hooks
cp redact_output.py ~/.claude/hooks/redact_output.py
chmod +x ~/.claude/hooks/redact_output.py
```

Verify:

```bash
python3 ~/.claude/hooks/redact_output.py --self-check
python3 ~/.claude/hooks/redact_output.py --list-rules
```

`--self-check` must report `0 failures` and exit 0. `--list-rules` prints every
rule name with `on` or `off`.

### 3. Wire into settings.json

Read `~/.claude/settings.json`. If it doesn't exist, create it with `{}`.

Add the PostToolUse hook. The `hooks` section should contain:

```json
"PostToolUse": [
  {
    "matcher": ".*",
    "hooks": [
      {
        "type": "command",
        "command": "/HOME/.claude/hooks/redact_output.py",
        "timeout": 30
      }
    ]
  }
]
```

Replace `/HOME/` with the actual home directory (`echo $HOME`).

If `hooks` or `PostToolUse` already exist, merge carefully — do not overwrite existing hooks.

### 4. Restart Claude Code

Hooks load at session start. Restart Claude Code to activate the hook.

### 5. Verify

After restart, write a file with a fake secret:

```bash
echo "DB_PASSWORD=hunter2xyz" > /tmp/redact_verify.txt
```

Then ask Claude to read `/tmp/redact_verify.txt`. The value must appear as `[REDACTED]`.

### 6. Optional: choose the rules

Eight rules are off by default: `email`, `ssn`, `iban`, `home_path`, `mac_addr`,
`public_ip`, `phone_loose`, `entropy`. Ask the user whether they want any of
them, and whether any default rule is wrong for their work. If so, write
`~/.claude/redact.toml`:

```toml
disable = ["phone"]
enable  = ["home_path", "email"]
allow   = ["example\\.com"]

[[rule]]
name    = "internal_ticket"
pattern = "ACME-\\d{6}"
```

Every replacement carries its rule name — `[REDACTED:env_secret]` — so the user
can read the name to disable straight out of the output.

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `REDACT_DISABLE` | unset | Comma-separated rule names to switch off |
| `REDACT_ENABLE` | unset | Comma-separated rule names to switch on |
| `REDACT_SKIP_TOOLS` | `WebFetch,WebSearch` | Comma-separated tool names to skip entirely |
| `REDACT_CONFIG` | `~/.claude/redact.toml` | Config file path |
| `REDACT_AGGRESSIVE` | unset | `1` is an alias for `REDACT_ENABLE=entropy` |
