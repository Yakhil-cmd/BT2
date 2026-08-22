# Q5984: enterprise/dotcom misclassification - renderInteractive in preview.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata make `renderInteractive` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L318) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:318](pkg/cmd/skills/preview/preview.go#L318) - `renderInteractive`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
