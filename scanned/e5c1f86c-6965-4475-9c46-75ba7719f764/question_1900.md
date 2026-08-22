# Q1900: nil dereference panic on hostile field - fetchReleasePath in fetch.go

## Question
Can an attacker-shaped response make `fetchReleasePath` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L281) dereference a nil pointer or index out of range, crashing gh mid-operation (leaving partial state on disk)?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:281](pkg/cmd/release/shared/fetch.go#L281) - `fetchReleasePath`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Return a response with nested nulls or empty arrays where gh expects data.
- Invariant to test: All response-derived structures are checked before dereference.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz the decoder with mutated payloads asserting no panic.
