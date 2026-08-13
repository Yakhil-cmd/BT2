# Q3349: Security-guidance review prompt pipeline prompt injection via diff via build refute prompt

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `build_refute_prompt` via `agentic review stage 2 prompt build` and control attacker-controlled diff content so that the codebase place instructions in diff content that cause the review model to skip dangerous behavior or leak extra context, breaking the invariant that truncation must not consistently drop the high-risk lines the user expects to be reviewed and leading to Cross-repo, cross-session, or wrong-target mutation with real security impact?

## Target
- File/function: `plugins/security-guidance/hooks/review_api.py` / `build_refute_prompt`
- Entrypoint: `agentic review stage 2 prompt build`
- Attacker controls: attacker-controlled diff content
- Exploit idea: Drive `agentic review stage 2 prompt build` with attacker-controlled attacker-controlled diff content and test whether `build_refute_prompt` changes security behavior in a way that place instructions in diff content that cause the review model to skip dangerous behavior or leak extra context.
- Invariant to test: truncation must not consistently drop the high-risk lines the user expects to be reviewed
- Expected Immunefi impact: Cross-repo, cross-session, or wrong-target mutation with real security impact
- Fast validation: build prompts from crafted diffs and assert the dangerous file or path remains present and correctly anchored after truncation and formatting
