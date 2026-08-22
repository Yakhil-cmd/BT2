# Q2403: browse/search listing triggers install or exec - newExtList in browse.go

## Question
Can data rendered or acted on by `newExtList` in [pkg/cmd/extension/browse/browse.go](pkg/cmd/extension/browse/browse.go#L110) (extension listings from the API) drive an install or execution without an explicit user decision on the exact repository?

## Target
- File/function: [pkg/cmd/extension/browse/browse.go:110](pkg/cmd/extension/browse/browse.go#L110) - `newExtList`
- Entrypoint: gh extension browse
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension that sorts into the listing the victim interacts with.
- Invariant to test: Installation always requires an explicit, fully qualified user confirmation.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting no install occurs without the confirmation path.
