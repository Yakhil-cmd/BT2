# Q0256: nil dereference panic on hostile field - fetchLatestRelease in http.go

## Question
Can an attacker-shaped response make `fetchLatestRelease` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L119) dereference a nil pointer or index out of range, crashing gh mid-operation (leaving partial state on disk)?

## Target
- File/function: [pkg/cmd/extension/http.go:119](pkg/cmd/extension/http.go#L119) - `fetchLatestRelease`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Return a response with nested nulls or empty arrays where gh expects data.
- Invariant to test: All response-derived structures are checked before dereference.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz the decoder with mutated payloads asserting no panic.
