# Q4946: default selection favors attacker option - chooseCodespaceFromList in common.go

## Question
Does `chooseCodespaceFromList` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L93) pre-select the first/default option from a server-ordered list, letting the attacker's entry be chosen by a bare Enter?

## Target
- File/function: [pkg/cmd/codespace/common.go:93](pkg/cmd/codespace/common.go#L93) - `chooseCodespaceFromList`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish an object that sorts first in the listing the prompt renders.
- Invariant to test: Defaults are gh-chosen, never index 0 of remote data, for security-relevant choices.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the default is the expected safe option.
