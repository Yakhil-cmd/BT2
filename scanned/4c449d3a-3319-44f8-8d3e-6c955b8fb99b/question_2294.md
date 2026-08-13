# Q2294: Shipped command workflow prompt injection via repo text via review pr command flow

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `/review-pr command flow` via `/review-pr` and control slash-command arguments provided by the user so that the codebase place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure, breaking the invariant that a shipped command must not exceed its declared tool scope because of untrusted content and leading to Cross-repo, cross-session, or wrong-target mutation with real security impact?

## Target
- File/function: `plugins/pr-review-toolkit/commands/review-pr.md` / `/review-pr command flow`
- Entrypoint: `/review-pr`
- Attacker controls: slash-command arguments provided by the user
- Exploit idea: Drive `/review-pr` with attacker-controlled slash-command arguments provided by the user and test whether `/review-pr command flow` changes security behavior in a way that place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure.
- Invariant to test: a shipped command must not exceed its declared tool scope because of untrusted content
- Expected Immunefi impact: Cross-repo, cross-session, or wrong-target mutation with real security impact
- Fast validation: run the command against a malicious repo or issue body and assert tool use remains within the intended target and approval scope
