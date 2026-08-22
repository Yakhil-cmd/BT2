# Q4384: regex catastrophic backtracking - FromFullNameWithHost in repo.go

## Question
Can a repo/remote/host string or API response field the attacker publishes feed a pathological string to the regular expression used in `FromFullNameWithHost` in [internal/ghrepo/repo.go](internal/ghrepo/repo.go#L52) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [internal/ghrepo/repo.go:52](internal/ghrepo/repo.go#L52) - `FromFullNameWithHost`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...).
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
