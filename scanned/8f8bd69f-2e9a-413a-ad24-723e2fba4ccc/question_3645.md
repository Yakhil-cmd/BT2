# Q3645: Shipped command workflow prompt injection via repo text via plugin dev create plugin flow

## Question
Can an unprivileged attacker while staying inside the public, unprivileged attacker model reach `/plugin-dev:create-plugin flow` via `/plugin-dev:create-plugin` and control slash-command arguments provided by the user so that the codebase place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure, breaking the invariant that a shipped command must not exceed its declared tool scope because of untrusted content and leading to Logic-level service disruption caused by bypassing a required guard or misbinding security state?

## Target
- File/function: `plugins/plugin-dev/commands/create-plugin.md` / `/plugin-dev:create-plugin flow`
- Entrypoint: `/plugin-dev:create-plugin`
- Attacker controls: slash-command arguments provided by the user
- Exploit idea: Drive `/plugin-dev:create-plugin` with attacker-controlled slash-command arguments provided by the user and test whether `/plugin-dev:create-plugin flow` changes security behavior in a way that place instructions in repo or issue text that steer the command into unauthorized tool use or data disclosure.
- Invariant to test: a shipped command must not exceed its declared tool scope because of untrusted content
- Expected Immunefi impact: Logic-level service disruption caused by bypassing a required guard or misbinding security state
- Fast validation: run the command against a malicious repo or issue body and assert tool use remains within the intended target and approval scope
