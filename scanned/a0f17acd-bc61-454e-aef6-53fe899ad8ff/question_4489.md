# Q4489: ref name starting with a dash - NewCmdDevelop in develop.go

## Question
Does `NewCmdDevelop` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L40) place a branch/ref/tag name from remote data in a git argv position where a leading `-` becomes an option (e.g. `--upload-pack=`)?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:40](pkg/cmd/issue/develop/develop.go#L40) - `NewCmdDevelop`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a PR branch or tag named `--upload-pack=touch /tmp/pwn`.
- Invariant to test: Ref values are validated against git's ref format and always follow `--`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test with hostile ref names asserting rejection or correct positioning.
