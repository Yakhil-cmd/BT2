# Q5366: default selection favors attacker option - selectSkill in preview.go

## Question
Does `selectSkill` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L453) pre-select the first/default option from a server-ordered list, letting the attacker's entry be chosen by a bare Enter?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:453](pkg/cmd/skills/preview/preview.go#L453) - `selectSkill`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an object that sorts first in the listing the prompt renders.
- Invariant to test: Defaults are gh-chosen, never index 0 of remote data, for security-relevant choices.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the default is the expected safe option.
