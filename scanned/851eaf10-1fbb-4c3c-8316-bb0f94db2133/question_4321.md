# Q4321: enterprise/dotcom misclassification - keyringServiceName in multi_account.go

## Question
Can a hostname, OAuth/device response, or git credential-protocol input the attacker supplies make `keyringServiceName` in [internal/config/migration/multi_account.go](internal/config/migration/multi_account.go#L222) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [internal/config/migration/multi_account.go:222](internal/config/migration/multi_account.go#L222) - `keyringServiceName`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
