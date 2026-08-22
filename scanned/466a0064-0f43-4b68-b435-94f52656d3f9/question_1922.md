# Q1922: numeric overflow / negative length - legacyJobLogFilenameRegexp in logs.go

## Question
Does `legacyJobLogFilenameRegexp` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L274) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [pkg/cmd/run/view/logs.go:274](pkg/cmd/run/view/logs.go#L274) - `legacyJobLogFilenameRegexp`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
