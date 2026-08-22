# Q5654: scheme downgrade on redirect - (App).VSCode in code.go

## Question
Can a redirect followed by `VSCode` in [pkg/cmd/codespace/code.go](pkg/cmd/codespace/code.go#L36) downgrade https to http (or to a non-HTTP scheme) while still sending credentials?

## Target
- File/function: [pkg/cmd/codespace/code.go:36](pkg/cmd/codespace/code.go#L36) - `(App).VSCode`
- Entrypoint: gh codespace code
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Redirect to `http://collector/` and observe the token in cleartext.
- Invariant to test: Only https targets are followed; other schemes abort the request.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting an http:// Location produces an error and no request is sent.
