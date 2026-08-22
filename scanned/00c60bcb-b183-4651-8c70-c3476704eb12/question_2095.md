# Q2095: error body echoed verbatim - filterCodespacesByRepoOwner in common.go

## Question
Does the error construction in `filterCodespacesByRepoOwner` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L262) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/codespace/common.go:262](pkg/cmd/codespace/common.go#L262) - `filterCodespacesByRepoOwner`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
