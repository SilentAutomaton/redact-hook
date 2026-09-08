# Working on redact-hook

Tier: 1

## What it is

A single-file PostToolUse hook for Claude Code. Claude Code pipes every tool
result through it before the model sees the result, so a key that appears in
`cat .env`, `wg show`, or an MCP call over SSH is replaced with `[REDACTED]`
and never reaches the transcript. Everything is regex; there is no network
call and no model. For anyone who runs Claude Code against real infrastructure.

## Running it

```
cp redact_output.py ~/.claude/hooks/redact_output.py
```

Then wire it into `~/.claude/settings.json` as a `PostToolUse` hook and restart
Claude Code. `README.md` has the JSON block.

## Checking it

```
python3 redact_output.py --self-check
```

## Rules

1. A new pattern ships as a named `Rule` with a default_on decision, a
   `_MUST_CUT` case **and** a `_MUST_KEEP` case.
   Over-redaction is the failure that makes the hook unusable: once ordinary
   code comes back mangled, people turn the hook off and the secrets flow
   again. Every pattern must prove it leaves normal text alone. `--self-check`
   fails if a default rule has no sample, so the rule table cannot outgrow its
   tests.
2. Nothing personal is committed. No keys, no home paths, no dumps. Sample
   data is invented; a real key never enters the repository.

## Commits

One step, one commit. A single line of plain English describing what the code
now does. No tool names, no attribution trailers.
