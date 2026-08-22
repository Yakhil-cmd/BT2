# Q5964: default selection favors attacker option - checkOverwrite in install.go

## Question
Does `checkOverwrite` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1045) pre-select the first/default option from a server-ordered list, letting the attacker's entry be chosen by a bare Enter?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1045](pkg/cmd/skills/install/install.go#L1045) - `checkOverwrite`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an object that sorts first in the listing the prompt renders.
- Invariant to test: Defaults are gh-chosen, never index 0 of remote data, for security-relevant choices.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the default is the expected safe option.
