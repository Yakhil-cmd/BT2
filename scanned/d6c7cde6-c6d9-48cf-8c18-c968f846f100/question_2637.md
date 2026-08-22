# Q2637: regex catastrophic backtracking - stepLogFilenameRegexp in logs.go

## Question
Can an asset, artifact, gist, or archive-member name and its bytes feed a pathological string to the regular expression used in `stepLogFilenameRegexp` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L280) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [pkg/cmd/run/view/logs.go:280](pkg/cmd/run/view/logs.go#L280) - `stepLogFilenameRegexp`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run gh run view.
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
