# Q2470: scheme downgrade on redirect - installRun in install.go

## Question
Can a redirect followed by `installRun` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L255) downgrade https to http (or to a non-HTTP scheme) while still sending credentials?

## Target
- File/function: [pkg/cmd/skills/install/install.go:255](pkg/cmd/skills/install/install.go#L255) - `installRun`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Redirect to `http://collector/` and observe the token in cleartext.
- Invariant to test: Only https targets are followed; other schemes abort the request.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting an http:// Location produces an error and no request is sent.
