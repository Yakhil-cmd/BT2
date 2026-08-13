# Q671: Security-guidance LLM review path overbroad exfiltration via build auth headers

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `_build_auth_headers` via `Anthropic review request header construction` and control repo-controlled diff content sent to review so that the codebase cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint, breaking the invariant that review traffic must not disclose more data than the user intended to review and leading to Unauthorized file read or write outside the user-approved workspace or target scope?

## Target
- File/function: `plugins/security-guidance/hooks/llm.py` / `_build_auth_headers`
- Entrypoint: `Anthropic review request header construction`
- Attacker controls: repo-controlled diff content sent to review
- Exploit idea: Drive `Anthropic review request header construction` with attacker-controlled repo-controlled diff content sent to review and test whether `_build_auth_headers` changes security behavior in a way that cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint.
- Invariant to test: review traffic must not disclose more data than the user intended to review
- Expected Immunefi impact: Unauthorized file read or write outside the user-approved workspace or target scope
- Fast validation: run review assembly in a repo containing attacker-controlled large files plus sensitive local files and assert only the intended in-scope content is sent
