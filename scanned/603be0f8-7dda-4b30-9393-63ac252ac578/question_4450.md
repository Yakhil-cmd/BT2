# Q4450: scheme downgrade on redirect - NewRemote in objects.go

## Question
Can a redirect followed by `NewRemote` in [git/objects.go](git/objects.go#L42) downgrade https to http (or to a non-HTTP scheme) while still sending credentials?

## Target
- File/function: [git/objects.go:42](git/objects.go#L42) - `NewRemote`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Redirect to `http://collector/` and observe the token in cleartext.
- Invariant to test: Only https targets are followed; other schemes abort the request.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting an http:// Location produces an error and no request is sent.
