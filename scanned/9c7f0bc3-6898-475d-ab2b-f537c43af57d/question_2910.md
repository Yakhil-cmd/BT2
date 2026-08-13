# Q2910: Shipped command workflow prompt injection via repo text via new sdk app command flow

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `/new-sdk-app command flow` via `/new-sdk-app` and control slash-command arguments provided by the user so that the codebase place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure, breaking the invariant that a shipped command must not exceed its declared tool scope because of untrusted content and leading to Security-control bypass that silently disables or routes around blocking, review, or permission boundaries?

## Target
- File/function: `plugins/agent-sdk-dev/commands/new-sdk-app.md` / `/new-sdk-app command flow`
- Entrypoint: `/new-sdk-app`
- Attacker controls: slash-command arguments provided by the user
- Exploit idea: Drive `/new-sdk-app` with attacker-controlled slash-command arguments provided by the user and test whether `/new-sdk-app command flow` changes security behavior in a way that place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure.
- Invariant to test: a shipped command must not exceed its declared tool scope because of untrusted content
- Expected Immunefi impact: Security-control bypass that silently disables or routes around blocking, review, or permission boundaries
- Fast validation: run the command against a malicious repo or issue body and assert tool use remains within the intended target and approval scope
