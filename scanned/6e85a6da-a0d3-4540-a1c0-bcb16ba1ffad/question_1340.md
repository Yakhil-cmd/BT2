# Q1340: Shipped command workflow prompt injection via repo text via cancel ralph command flow

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `/cancel-ralph command flow` via `/cancel-ralph` and control slash-command arguments provided by the user so that the codebase place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure, breaking the invariant that a shipped command must not exceed its declared tool scope because of untrusted content and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/ralph-wiggum/commands/cancel-ralph.md` / `/cancel-ralph command flow`
- Entrypoint: `/cancel-ralph`
- Attacker controls: slash-command arguments provided by the user
- Exploit idea: Drive `/cancel-ralph` with attacker-controlled slash-command arguments provided by the user and test whether `/cancel-ralph command flow` changes security behavior in a way that place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure.
- Invariant to test: a shipped command must not exceed its declared tool scope because of untrusted content
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: run the command against a malicious repo or issue body and assert tool use remains within the intended target and approval scope
