# Q3666: enterprise/dotcom misclassification - CategorizeHost in host.go

## Question
Can a repo/remote/host string or API response field the attacker publishes make `CategorizeHost` in [internal/ghinstance/host.go](internal/ghinstance/host.go#L100) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [internal/ghinstance/host.go:100](internal/ghinstance/host.go#L100) - `CategorizeHost`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
