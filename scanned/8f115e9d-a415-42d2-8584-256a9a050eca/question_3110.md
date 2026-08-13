# Q3110: Security-guidance LLM review path overbroad exfiltration via cap files for prompt

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `_cap_files_for_prompt` via `review file truncation` and control repo-controlled diff content sent to review so that the codebase cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint, breaking the invariant that review traffic must not disclose more data than the user intended to review and leading to Logic-level service disruption caused by bypassing a required guard or misbinding security state?

## Target
- File/function: `plugins/security-guidance/hooks/llm.py` / `_cap_files_for_prompt`
- Entrypoint: `review file truncation`
- Attacker controls: repo-controlled diff content sent to review
- Exploit idea: Drive `review file truncation` with attacker-controlled repo-controlled diff content sent to review and test whether `_cap_files_for_prompt` changes security behavior in a way that cause the review path to send unrelated local files, prompts, or secrets to the remote model endpoint.
- Invariant to test: review traffic must not disclose more data than the user intended to review
- Expected Immunefi impact: Logic-level service disruption caused by bypassing a required guard or misbinding security state
- Fast validation: run review assembly in a repo containing attacker-controlled large files plus sensitive local files and assert only the intended in-scope content is sent
