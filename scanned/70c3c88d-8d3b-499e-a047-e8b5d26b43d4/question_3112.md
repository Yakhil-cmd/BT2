# Q3112: Security-guidance LLM review path overbroad exfiltration via is 3p provider

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `_is_3p_provider` via `provider routing for review calls` and control repo-controlled diff content sent to review so that the codebase cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint, breaking the invariant that review traffic must not disclose more data than the user intended to review and leading to Logic-level service disruption caused by bypassing a required guard or misbinding security state?

## Target
- File/function: `plugins/security-guidance/hooks/llm.py` / `_is_3p_provider`
- Entrypoint: `provider routing for review calls`
- Attacker controls: repo-controlled diff content sent to review
- Exploit idea: Drive `provider routing for review calls` with attacker-controlled repo-controlled diff content sent to review and test whether `_is_3p_provider` changes security behavior in a way that cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint.
- Invariant to test: review traffic must not disclose more data than the user intended to review
- Expected Immunefi impact: Logic-level service disruption caused by bypassing a required guard or misbinding security state
- Fast validation: run review assembly in a repo containing attacker-controlled large files plus sensitive local files and assert only the intended in-scope content is sent
