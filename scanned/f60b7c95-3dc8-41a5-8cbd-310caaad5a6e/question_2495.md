# Q2495: regex catastrophic backtracking - NewCmdUpdate in update.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata feed a pathological string to the regular expression used in `NewCmdUpdate` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L66) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [pkg/cmd/skills/update/update.go:66](pkg/cmd/skills/update/update.go#L66) - `NewCmdUpdate`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run gh skills update.
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
