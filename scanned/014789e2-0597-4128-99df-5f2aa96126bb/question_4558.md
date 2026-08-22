# Q4558: token attached to non-matching host - authRecoveryCommand in cmd.go

## Question
Can `authRecoveryCommand` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L304) attach the token stored for one host to a request whose host was derived from an extension repository, its release assets, and its manifest fields?

## Target
- File/function: [internal/ghcmd/cmd.go:304](internal/ghcmd/cmd.go#L304) - `authRecoveryCommand`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a repo/remote that resolves to a host the attacker controls while the victim's active token is for github.com.
- Invariant to test: A token is only ever sent to the exact host it was issued for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test with two configured hosts asserting the header matches the request host.
