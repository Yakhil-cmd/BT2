# Q3743: ref name with control characters reaches output and argv - (gitExecuter).CreateBranch in git.go

## Question
Does `CreateBranch` in [pkg/cmd/repo/sync/git.go](pkg/cmd/repo/sync/git.go#L35) accept ref names containing control characters, spaces, or `..` that git itself would reject, letting the value flow further into gh's own logic?

## Target
- File/function: [pkg/cmd/repo/sync/git.go:35](pkg/cmd/repo/sync/git.go#L35) - `(gitExecuter).CreateBranch`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Create refs via the API with unusual names allowed by the server but not by gh's assumptions.
- Invariant to test: gh validates refs with git's check-ref-format rules before use.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Fuzz ref names asserting validation.
