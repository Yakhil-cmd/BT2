# Q3016: regex catastrophic backtracking - parseRemoteURLOrName in client.go

## Question
Can a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes feed a pathological string to the regular expression used in `parseRemoteURLOrName` in [git/client.go](git/client.go#L1026) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [git/client.go:1026](git/client.go#L1026) - `parseRemoteURLOrName`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run gh repo clone.
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
