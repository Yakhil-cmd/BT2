# Q4065: nil dereference panic on hostile field - stepLogFilenameRegexp in logs.go

## Question
Can an attacker-shaped response make `stepLogFilenameRegexp` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L280) dereference a nil pointer or index out of range, crashing gh mid-operation (leaving partial state on disk)?

## Target
- File/function: [pkg/cmd/run/view/logs.go:280](pkg/cmd/run/view/logs.go#L280) - `stepLogFilenameRegexp`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Return a response with nested nulls or empty arrays where gh expects data.
- Invariant to test: All response-derived structures are checked before dereference.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz the decoder with mutated payloads asserting no panic.
