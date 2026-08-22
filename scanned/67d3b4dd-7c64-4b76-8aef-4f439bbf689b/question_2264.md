# Q2264: repo coordinates control the request host - EnableRepoOverride in repo_override.go

## Question
Can attacker-published repository coordinates or remotes flowing into `EnableRepoOverride` in [pkg/cmdutil/repo_override.go](pkg/cmdutil/repo_override.go#L36) determine the API base URL for an authenticated request?

## Target
- File/function: [pkg/cmdutil/repo_override.go:36](pkg/cmdutil/repo_override.go#L36) - `EnableRepoOverride`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo/remote whose parsed host becomes the API target while the victim's token is attached.
- Invariant to test: The API base URL comes from the authenticated host configuration only.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with hostile coordinates asserting the request URL host.
