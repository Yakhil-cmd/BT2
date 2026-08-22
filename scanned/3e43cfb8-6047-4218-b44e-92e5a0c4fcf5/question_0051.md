# Q0051: default selection favors attacker option - logoutRun in logout.go

## Question
Does `logoutRun` in [pkg/cmd/auth/logout/logout.go](pkg/cmd/auth/logout/logout.go#L79) pre-select the first/default option from a server-ordered list, letting the attacker's entry be chosen by a bare Enter?

## Target
- File/function: [pkg/cmd/auth/logout/logout.go:79](pkg/cmd/auth/logout/logout.go#L79) - `logoutRun`
- Entrypoint: gh auth logout
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish an object that sorts first in the listing the prompt renders.
- Invariant to test: Defaults are gh-chosen, never index 0 of remote data, for security-relevant choices.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the default is the expected safe option.
