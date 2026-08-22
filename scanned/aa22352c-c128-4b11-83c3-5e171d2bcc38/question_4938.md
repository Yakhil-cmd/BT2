# Q4938: index/label mismatch after filtering - (App).ForwardPorts in ports.go

## Question
Can the option list built in `ForwardPorts` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L324) be filtered or deduplicated so the chosen index maps to a different underlying object than the label shown?

## Target
- File/function: [pkg/cmd/codespace/ports.go:324](pkg/cmd/codespace/ports.go#L324) - `(App).ForwardPorts`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish entries whose labels collide after truncation/dedup.
- Invariant to test: Selection returns the object identity, not a recomputed index.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with colliding labels asserting the selected object matches the label.
