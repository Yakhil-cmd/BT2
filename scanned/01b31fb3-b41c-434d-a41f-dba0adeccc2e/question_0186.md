# Q186: Security-guidance LLM review path overbroad exfiltration via call claude dual or

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `_call_claude_dual_or` via `dual review call fallback` and control repo-controlled diff content sent to review so that the codebase cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint, breaking the invariant that review traffic must not disclose more data than the user intended to review and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/llm.py` / `_call_claude_dual_or`
- Entrypoint: `dual review call fallback`
- Attacker controls: repo-controlled diff content sent to review
- Exploit idea: Drive `dual review call fallback` with attacker-controlled repo-controlled diff content sent to review and test whether `_call_claude_dual_or` changes security behavior in a way that cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint.
- Invariant to test: review traffic must not disclose more data than the user intended to review
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: run review assembly in a repo containing attacker-controlled large files plus sensitive local files and assert only the intended in-scope content is sent
