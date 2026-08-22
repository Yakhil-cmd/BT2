# Q2779: unbounded response body - (API).do in api.go

## Question
Does `do` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L1278) read the whole response body into memory without a limit, so an attacker-controlled endpoint can exhaust the victim's RAM?

## Target
- File/function: [internal/codespaces/api/api.go:1278](internal/codespaces/api/api.go#L1278) - `(API).do`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Serve a multi-gigabyte body from an attacker-controlled host or asset URL.
- Invariant to test: Response reads are wrapped in a limit reader with an explicit cap.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a huge/endless body asserting a bounded error.
