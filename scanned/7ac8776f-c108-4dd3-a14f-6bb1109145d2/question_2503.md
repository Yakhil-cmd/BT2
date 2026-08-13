# Q2503: Security-guidance LLM review path overbroad exfiltration via call claude

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `_call_claude` via `single-shot review call` and control repo-controlled diff content sent to review so that the codebase cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint, breaking the invariant that review traffic must not disclose more data than the user intended to review and leading to Security-control bypass that silently disables or routes around blocking, review, or permission boundaries?

## Target
- File/function: `plugins/security-guidance/hooks/llm.py` / `_call_claude`
- Entrypoint: `single-shot review call`
- Attacker controls: repo-controlled diff content sent to review
- Exploit idea: Drive `single-shot review call` with attacker-controlled repo-controlled diff content sent to review and test whether `_call_claude` changes security behavior in a way that cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint.
- Invariant to test: review traffic must not disclose more data than the user intended to review
- Expected Immunefi impact: Security-control bypass that silently disables or routes around blocking, review, or permission boundaries
- Fast validation: run review assembly in a repo containing attacker-controlled large files plus sensitive local files and assert only the intended in-scope content is sent
