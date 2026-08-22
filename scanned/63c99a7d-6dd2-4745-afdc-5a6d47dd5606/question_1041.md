# Q1041: regex catastrophic backtracking - NewCmdInstall in install.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata feed a pathological string to the regular expression used in `NewCmdInstall` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L76) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [pkg/cmd/skills/install/install.go:76](pkg/cmd/skills/install/install.go#L76) - `NewCmdInstall`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run gh skills install.
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
