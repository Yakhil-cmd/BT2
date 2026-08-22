# Q1724: regex catastrophic backtracking - readFrom in lockfile.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata feed a pathological string to the regular expression used in `readFrom` in [internal/skills/lockfile/lockfile.go](internal/skills/lockfile/lockfile.go#L53) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [internal/skills/lockfile/lockfile.go:53](internal/skills/lockfile/lockfile.go#L53) - `readFrom`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run gh skills install.
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
