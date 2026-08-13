# Q298: Security-guidance review prompt pipeline prompt injection via diff via build investigate prompt

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `build_investigate_prompt` via `agentic review stage 1 prompt build` and control attacker-controlled diff content so that the codebase place instructions in diff content that cause the review model to skip dangerous behavior or leak extra context, breaking the invariant that prompt assembly must not let untrusted repo content suppress review of dangerous changes and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/security-guidance/hooks/review_api.py` / `build_investigate_prompt`
- Entrypoint: `agentic review stage 1 prompt build`
- Attacker controls: attacker-controlled diff content
- Exploit idea: Drive `agentic review stage 1 prompt build` with attacker-controlled attacker-controlled diff content and test whether `build_investigate_prompt` changes security behavior in a way that place instructions in diff content that cause the review model to skip dangerous behavior or leak extra context.
- Invariant to test: prompt assembly must not let untrusted repo content suppress review of dangerous changes
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: build prompts from crafted diffs and assert the dangerous file or path remains present and correctly anchored after truncation and formatting
