# Q4268: enterprise/dotcom misclassification - setRun in set.go

## Question
Can an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes make `setRun` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L203) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [pkg/cmd/secret/set/set.go:203](pkg/cmd/secret/set/set.go#L203) - `setRun`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
