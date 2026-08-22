# Q3954: token attached to non-matching host - checkSecuritySettings in publish.go

## Question
Can `checkSecuritySettings` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L790) attach the token stored for one host to a request whose host was derived from a published skill's archive entries, frontmatter, and registry metadata?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:790](pkg/cmd/skills/publish/publish.go#L790) - `checkSecuritySettings`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a repo/remote that resolves to a host the attacker controls while the victim's active token is for github.com.
- Invariant to test: A token is only ever sent to the exact host it was issued for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test with two configured hosts asserting the header matches the request host.
