# Q3023: Shipped command workflow prompt injection via repo text via clean gone command flow

## Question
Can an unprivileged attacker while staying inside the public, unprivileged attacker model reach `/clean_gone command flow` via `/clean_gone` and control slash-command arguments provided by the user so that the codebase place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure, breaking the invariant that a shipped command must not exceed its declared tool scope because of untrusted content and leading to Security-control bypass that silently disables or routes around blocking, review, or permission boundaries?

## Target
- File/function: `plugins/commit-commands/commands/clean_gone.md` / `/clean_gone command flow`
- Entrypoint: `/clean_gone`
- Attacker controls: slash-command arguments provided by the user
- Exploit idea: Drive `/clean_gone` with attacker-controlled slash-command arguments provided by the user and test whether `/clean_gone command flow` changes security behavior in a way that place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure.
- Invariant to test: a shipped command must not exceed its declared tool scope because of untrusted content
- Expected Immunefi impact: Security-control bypass that silently disables or routes around blocking, review, or permission boundaries
- Fast validation: run the command against a malicious repo or issue body and assert tool use remains within the intended target and approval scope
