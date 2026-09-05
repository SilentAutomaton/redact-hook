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
```

It must report `0 failures` and exit 0.

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

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `REDACT_AGGRESSIVE` | unset | Set to `1` to also redact 32+ char hex strings and 40+ char opaque strings |
| `REDACT_SKIP_TOOLS` | `WebFetch,WebSearch` | Comma-separated tool names to skip entirely |
