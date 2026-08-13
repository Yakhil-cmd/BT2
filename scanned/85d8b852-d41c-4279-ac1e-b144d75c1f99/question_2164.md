# Q2164: Shipped command workflow prompt injection via repo text via feature dev command flow

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `/feature-dev command flow` via `/feature-dev` and control slash-command arguments provided by the user so that the codebase place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure, breaking the invariant that a shipped command must not exceed its declared tool scope because of untrusted content and leading to Cross-repo, cross-session, or wrong-target mutation with real security impact?

## Target
- File/function: `plugins/feature-dev/commands/feature-dev.md` / `/feature-dev command flow`
- Entrypoint: `/feature-dev`
- Attacker controls: slash-command arguments provided by the user
- Exploit idea: Drive `/feature-dev` with attacker-controlled slash-command arguments provided by the user and test whether `/feature-dev command flow` changes security behavior in a way that place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure.
- Invariant to test: a shipped command must not exceed its declared tool scope because of untrusted content
- Expected Immunefi impact: Cross-repo, cross-session, or wrong-target mutation with real security impact
- Fast validation: run the command against a malicious repo or issue body and assert tool use remains within the intended target and approval scope
