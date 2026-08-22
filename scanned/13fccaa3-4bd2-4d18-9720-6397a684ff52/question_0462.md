# Q0462: YAML/frontmatter expansion or injection - printVerifiedSubjects in verify.go

## Question
Does the frontmatter/YAML parsing in `printVerifiedSubjects` in [pkg/cmd/release/verify/verify.go](pkg/cmd/release/verify/verify.go#L196) allow anchors/aliases, duplicate keys, or unexpected fields from remote content to override a validated value?

## Target
- File/function: [pkg/cmd/release/verify/verify.go:196](pkg/cmd/release/verify/verify.go#L196) - `printVerifiedSubjects`
- Entrypoint: gh release verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a skill/template whose frontmatter redefines a field gh already validated.
- Invariant to test: Parsing is strict: known fields only, duplicates and aliases rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with duplicate/alias frontmatter asserting an error.
