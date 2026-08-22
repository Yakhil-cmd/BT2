# Q5574: copy-to-clipboard / OSC 52 path - sortComments in comments.go

## Question
Can content rendered by `sortComments` in [pkg/cmd/pr/shared/comments.go](pkg/cmd/pr/shared/comments.go#L144) write to the victim's clipboard via OSC 52, staging a command for the next paste?

## Target
- File/function: [pkg/cmd/pr/shared/comments.go:144](pkg/cmd/pr/shared/comments.go#L144) - `sortComments`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a body containing an OSC 52 payload.
- Invariant to test: OSC sequences are stripped from all remote text.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting OSC 52 bytes never appear in output.
