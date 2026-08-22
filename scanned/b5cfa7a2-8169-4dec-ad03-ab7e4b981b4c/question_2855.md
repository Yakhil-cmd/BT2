# Q2855: regex catastrophic backtracking - getStateEntry in update.go

## Question
Can an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes feed a pathological string to the regular expression used in `getStateEntry` in [internal/update/update.go](internal/update/update.go#L147) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [internal/update/update.go:147](internal/update/update.go#L147) - `getStateEntry`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run gh alias import.
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
