# Q0089: enterprise/dotcom misclassification - TenantName in host.go

## Question
Can a repo/remote/host string or API response field the attacker publishes make `TenantName` in [internal/ghinstance/host.go](internal/ghinstance/host.go#L27) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [internal/ghinstance/host.go:27](internal/ghinstance/host.go#L27) - `TenantName`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
