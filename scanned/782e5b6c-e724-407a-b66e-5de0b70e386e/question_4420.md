# Q4420: ref name with control characters reaches output and argv - CredentialPatternFromGitURL in client.go

## Question
Does `CredentialPatternFromGitURL` in [git/client.go](git/client.go#L123) accept ref names containing control characters, spaces, or `..` that git itself would reject, letting the value flow further into gh's own logic?

## Target
- File/function: [git/client.go:123](git/client.go#L123) - `CredentialPatternFromGitURL`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Create refs via the API with unusual names allowed by the server but not by gh's assumptions.
- Invariant to test: gh validates refs with git's check-ref-format rules before use.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Fuzz ref names asserting validation.
