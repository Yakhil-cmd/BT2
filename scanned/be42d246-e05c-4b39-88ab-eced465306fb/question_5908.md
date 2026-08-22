# Q5908: error body echoed verbatim - checkForUpdate in cmd.go

## Question
Does the error construction in `checkForUpdate` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L318) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [internal/ghcmd/cmd.go:318](internal/ghcmd/cmd.go#L318) - `checkForUpdate`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
