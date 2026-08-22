# Q4058: enterprise/dotcom misclassification - (apiLogFetcher).GetLog in logs.go

## Question
Can an asset, artifact, gist, or archive-member name and its bytes make `GetLog` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L42) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [pkg/cmd/run/view/logs.go:42](pkg/cmd/run/view/logs.go#L42) - `(apiLogFetcher).GetLog`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
