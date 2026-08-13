# Q1775: Security-guidance LLM review path overbroad exfiltration via analyze security concerns

## Question
Can an unprivileged attacker while staying inside the public, unprivileged attacker model reach `analyze_security_concerns` via `areas-of-concern analysis` and control repo-controlled diff content sent to review so that the codebase cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint, breaking the invariant that review traffic must not disclose more data than the user intended to review and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/security-guidance/hooks/llm.py` / `analyze_security_concerns`
- Entrypoint: `areas-of-concern analysis`
- Attacker controls: repo-controlled diff content sent to review
- Exploit idea: Drive `areas-of-concern analysis` with attacker-controlled repo-controlled diff content sent to review and test whether `analyze_security_concerns` changes security behavior in a way that cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint.
- Invariant to test: review traffic must not disclose more data than the user intended to review
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: run review assembly in a repo containing attacker-controlled large files plus sensitive local files and assert only the intended in-scope content is sent
