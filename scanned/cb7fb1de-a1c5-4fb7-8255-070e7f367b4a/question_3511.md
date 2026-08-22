# Q3511: default selection favors attacker option - (App).ForwardPorts in ports.go

## Question
Does `ForwardPorts` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L324) pre-select the first/default option from a server-ordered list, letting the attacker's entry be chosen by a bare Enter?

## Target
- File/function: [pkg/cmd/codespace/ports.go:324](pkg/cmd/codespace/ports.go#L324) - `(App).ForwardPorts`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish an object that sorts first in the listing the prompt renders.
- Invariant to test: Defaults are gh-chosen, never index 0 of remote data, for security-relevant choices.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the default is the expected safe option.
