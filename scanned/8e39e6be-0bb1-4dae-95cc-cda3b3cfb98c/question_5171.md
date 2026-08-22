# Q5171: ref name starting with a dash - (gitExecuter).CurrentBranch in git.go

## Question
Does `CurrentBranch` in [pkg/cmd/repo/sync/git.go](pkg/cmd/repo/sync/git.go#L52) place a branch/ref/tag name from remote data in a git argv position where a leading `-` becomes an option (e.g. `--upload-pack=`)?

## Target
- File/function: [pkg/cmd/repo/sync/git.go:52](pkg/cmd/repo/sync/git.go#L52) - `(gitExecuter).CurrentBranch`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a PR branch or tag named `--upload-pack=touch /tmp/pwn`.
- Invariant to test: Ref values are validated against git's ref format and always follow `--`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test with hostile ref names asserting rejection or correct positioning.
