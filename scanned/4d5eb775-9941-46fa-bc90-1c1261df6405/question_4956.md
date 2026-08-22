# Q4956: regex catastrophic backtracking - ParseSessionIDFromURL in capi.go

## Question
Can an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes feed a pathological string to the regular expression used in `ParseSessionIDFromURL` in [pkg/cmd/agent-task/shared/capi.go](pkg/cmd/agent-task/shared/capi.go#L78) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [pkg/cmd/agent-task/shared/capi.go:78](pkg/cmd/agent-task/shared/capi.go#L78) - `ParseSessionIDFromURL`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run gh agent task.
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
