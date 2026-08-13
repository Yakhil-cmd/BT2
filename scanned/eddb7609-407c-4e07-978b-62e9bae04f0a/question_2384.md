# Q2384: Security-guidance LLM review path overbroad exfiltration via agentic review

## Question
Can an unprivileged attacker while staying inside the public, unprivileged attacker model reach `agentic_review` via `commit-review and push-sweep review` and control repo-controlled diff content sent to review so that the codebase cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint, breaking the invariant that review traffic must not disclose more data than the user intended to review and leading to Cross-repo, cross-session, or wrong-target mutation with real security impact?

## Target
- File/function: `plugins/security-guidance/hooks/llm.py` / `agentic_review`
- Entrypoint: `commit-review and push-sweep review`
- Attacker controls: repo-controlled diff content sent to review
- Exploit idea: Drive `commit-review and push-sweep review` with attacker-controlled repo-controlled diff content sent to review and test whether `agentic_review` changes security behavior in a way that cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint.
- Invariant to test: review traffic must not disclose more data than the user intended to review
- Expected Immunefi impact: Cross-repo, cross-session, or wrong-target mutation with real security impact
- Fast validation: run review assembly in a repo containing attacker-controlled large files plus sensitive local files and assert only the intended in-scope content is sent
