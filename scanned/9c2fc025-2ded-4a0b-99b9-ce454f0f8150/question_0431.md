# Q431: Security-guidance LLM review path overbroad exfiltration via analyze code security

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `analyze_code_security` via `Stop-hook diff review` and control repo-controlled diff content sent to review so that the codebase cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint, breaking the invariant that review traffic must not disclose more data than the user intended to review and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/llm.py` / `analyze_code_security`
- Entrypoint: `Stop-hook diff review`
- Attacker controls: repo-controlled diff content sent to review
- Exploit idea: Drive `Stop-hook diff review` with attacker-controlled repo-controlled diff content sent to review and test whether `analyze_code_security` changes security behavior in a way that cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint.
- Invariant to test: review traffic must not disclose more data than the user intended to review
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: run review assembly in a repo containing attacker-controlled large files plus sensitive local files and assert only the intended in-scope content is sent
