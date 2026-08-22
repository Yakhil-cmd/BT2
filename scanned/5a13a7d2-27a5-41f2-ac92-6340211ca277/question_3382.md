# Q3382: regex catastrophic backtracking - (Untrusted).UnmarshalJSON in untrusted.go

## Question
Can an issue/PR title, body, comment, check output, or release note the attacker authored feed a pathological string to the regular expression used in `UnmarshalJSON` in [pkg/iostreams/untrusted.go](pkg/iostreams/untrusted.go#L63) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [pkg/iostreams/untrusted.go:63](pkg/iostreams/untrusted.go#L63) - `(Untrusted).UnmarshalJSON`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run gh pr view.
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
