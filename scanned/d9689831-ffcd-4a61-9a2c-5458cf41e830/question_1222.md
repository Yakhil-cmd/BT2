# Q1222: scheme downgrade on redirect - GistIDFromURL in shared.go

## Question
Can a redirect followed by `GistIDFromURL` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L84) downgrade https to http (or to a non-HTTP scheme) while still sending credentials?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:84](pkg/cmd/gist/shared/shared.go#L84) - `GistIDFromURL`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Redirect to `http://collector/` and observe the token in cleartext.
- Invariant to test: Only https targets are followed; other schemes abort the request.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting an http:// Location produces an error and no request is sent.
