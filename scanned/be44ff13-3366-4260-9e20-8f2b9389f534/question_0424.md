# Q424: Security-guidance review prompt pipeline prompt injection via diff via format findings

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `format_findings` via `finding text emitted back to Claude Code` and control attacker-controlled diff content so that the codebase place instructions in diff content that cause the review model to skip dangerous behavior or leak extra context, breaking the invariant that prompt assembly must not let untrusted repo content suppress review of dangerous changes and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/security-guidance/hooks/review_api.py` / `format_findings`
- Entrypoint: `finding text emitted back to Claude Code`
- Attacker controls: attacker-controlled diff content
- Exploit idea: Drive `finding text emitted back to Claude Code` with attacker-controlled attacker-controlled diff content and test whether `format_findings` changes security behavior in a way that place instructions in diff content that cause the review model to skip dangerous behavior or leak extra context.
- Invariant to test: prompt assembly must not let untrusted repo content suppress review of dangerous changes
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: build prompts from crafted diffs and assert the dangerous file or path remains present and correctly anchored after truncation and formatting
