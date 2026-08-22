# Q5903: regex catastrophic backtracking - expandAlias in alias.go

## Question
Can an extension repository, its release assets, and its manifest fields feed a pathological string to the regular expression used in `expandAlias` in [pkg/cmd/root/alias.go](pkg/cmd/root/alias.go#L79) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [pkg/cmd/root/alias.go:79](pkg/cmd/root/alias.go#L79) - `expandAlias`
- Entrypoint: gh root alias
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run gh root alias.
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
