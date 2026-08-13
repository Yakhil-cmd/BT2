# Q1517: Security-guidance review prompt pipeline prompt injection via diff via cap diff for prompt

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `cap_diff_for_prompt` via `review prompt truncation` and control attacker-controlled diff content so that the codebase place instructions in diff content that cause the review model to skip dangerous behavior or leak extra context, breaking the invariant that prompt assembly must not let untrusted repo content suppress review of dangerous changes and leading to Security-control bypass that silently disables or routes around blocking, review, or permission boundaries?

## Target
- File/function: `plugins/security-guidance/hooks/review_api.py` / `cap_diff_for_prompt`
- Entrypoint: `review prompt truncation`
- Attacker controls: attacker-controlled diff content
- Exploit idea: Drive `review prompt truncation` with attacker-controlled attacker-controlled diff content and test whether `cap_diff_for_prompt` changes security behavior in a way that place instructions in diff content that cause the review model to skip dangerous behavior or leak extra context.
- Invariant to test: prompt assembly must not let untrusted repo content suppress review of dangerous changes
- Expected Immunefi impact: Security-control bypass that silently disables or routes around blocking, review, or permission boundaries
- Fast validation: build prompts from crafted diffs and assert the dangerous file or path remains present and correctly anchored after truncation and formatting
