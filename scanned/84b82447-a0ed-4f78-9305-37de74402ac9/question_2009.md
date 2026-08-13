# Q2009: Security-guidance review prompt pipeline prompt injection via diff via filter by severity

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `filter_by_severity` via `finding triage after agentic review` and control attacker-controlled diff content so that the codebase place instructions in diff content that cause the review model to skip dangerous behavior or leak extra context, breaking the invariant that prompt assembly must not let untrusted repo content suppress review of dangerous changes and leading to Logic-level service disruption caused by bypassing a required guard or misbinding security state?

## Target
- File/function: `plugins/security-guidance/hooks/review_api.py` / `filter_by_severity`
- Entrypoint: `finding triage after agentic review`
- Attacker controls: attacker-controlled diff content
- Exploit idea: Drive `finding triage after agentic review` with attacker-controlled attacker-controlled diff content and test whether `filter_by_severity` changes security behavior in a way that place instructions in diff content that cause the review model to skip dangerous behavior or leak extra context.
- Invariant to test: prompt assembly must not let untrusted repo content suppress review of dangerous changes
- Expected Immunefi impact: Logic-level service disruption caused by bypassing a required guard or misbinding security state
- Fast validation: build prompts from crafted diffs and assert the dangerous file or path remains present and correctly anchored after truncation and formatting
