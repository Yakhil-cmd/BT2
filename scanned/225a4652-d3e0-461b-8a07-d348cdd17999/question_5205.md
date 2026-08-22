# Q5205: pagination Link header points off-host - linkedBranchRepoFromURL in develop.go

## Question
Does `linkedBranchRepoFromURL` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L306) follow the `Link: rel=next` URL from the response without re-validating its host against the original request host?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:306](pkg/cmd/issue/develop/develop.go#L306) - `linkedBranchRepoFromURL`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Return a Link header pointing at the attacker's collector on the first page.
- Invariant to test: Pagination targets must match the origin host and scheme.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test returning a cross-host Link and asserting no authenticated follow-up request.
