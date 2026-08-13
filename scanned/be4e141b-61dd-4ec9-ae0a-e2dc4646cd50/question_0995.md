# Q995: Shipped command workflow prompt injection via repo text via hookify help flow

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `/hookify:help flow` via `/hookify:help` and control slash-command arguments provided by the user so that the codebase place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure, breaking the invariant that a shipped command must not exceed its declared tool scope because of untrusted content and leading to Unauthorized file read or write outside the user-approved workspace or target scope?

## Target
- File/function: `plugins/hookify/commands/help.md` / `/hookify:help flow`
- Entrypoint: `/hookify:help`
- Attacker controls: slash-command arguments provided by the user
- Exploit idea: Drive `/hookify:help` with attacker-controlled slash-command arguments provided by the user and test whether `/hookify:help flow` changes security behavior in a way that place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure.
- Invariant to test: a shipped command must not exceed its declared tool scope because of untrusted content
- Expected Immunefi impact: Unauthorized file read or write outside the user-approved workspace or target scope
- Fast validation: run the command against a malicious repo or issue body and assert tool use remains within the intended target and approval scope
