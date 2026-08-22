# Q4406: DNS rebinding between check and connect - EnableRepoOverride in repo_override.go

## Question
Does `EnableRepoOverride` in [pkg/cmdutil/repo_override.go](pkg/cmdutil/repo_override.go#L36) validate a hostname and then dial it later, allowing a rebinding attacker to pass the check and serve a different address?

## Target
- File/function: [pkg/cmdutil/repo_override.go:36](pkg/cmdutil/repo_override.go#L36) - `EnableRepoOverride`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Serve a short-TTL record that flips after validation.
- Invariant to test: Validation is host-based and enforced at dial time by the same transport.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting validation happens in the transport, not only before it.
