# Q365: Shipped command workflow prompt injection via repo text via ralph help command flow

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `/ralph help command flow` via `/ralph help` and control slash-command arguments provided by the user so that the codebase place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure, breaking the invariant that a shipped command must not exceed its declared tool scope because of untrusted content and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/ralph-wiggum/commands/help.md` / `/ralph help command flow`
- Entrypoint: `/ralph help`
- Attacker controls: slash-command arguments provided by the user
- Exploit idea: Drive `/ralph help` with attacker-controlled slash-command arguments provided by the user and test whether `/ralph help command flow` changes security behavior in a way that place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure.
- Invariant to test: a shipped command must not exceed its declared tool scope because of untrusted content
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: run the command against a malicious repo or issue body and assert tool use remains within the intended target and approval scope
