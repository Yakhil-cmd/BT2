# Q0510: default selection favors attacker option - PromptGists in shared.go

## Question
Does `PromptGists` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L228) pre-select the first/default option from a server-ordered list, letting the attacker's entry be chosen by a bare Enter?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:228](pkg/cmd/gist/shared/shared.go#L228) - `PromptGists`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object that sorts first in the listing the prompt renders.
- Invariant to test: Defaults are gh-chosen, never index 0 of remote data, for security-relevant choices.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the default is the expected safe option.
