# Q0166: pagination Link header points off-host - NewRemote in objects.go

## Question
Does `NewRemote` in [git/objects.go](git/objects.go#L42) follow the `Link: rel=next` URL from the response without re-validating its host against the original request host?

## Target
- File/function: [git/objects.go:42](git/objects.go#L42) - `NewRemote`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Return a Link header pointing at the attacker's collector on the first page.
- Invariant to test: Pagination targets must match the origin host and scheme.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test returning a cross-host Link and asserting no authenticated follow-up request.
