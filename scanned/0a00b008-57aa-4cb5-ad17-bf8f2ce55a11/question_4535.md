# Q4535: ref name starting with a dash - (gitExecuter).Remotes in git.go

## Question
Does `Remotes` in [pkg/cmd/extension/git.go](pkg/cmd/extension/git.go#L58) place a branch/ref/tag name from remote data in a git argv position where a leading `-` becomes an option (e.g. `--upload-pack=`)?

## Target
- File/function: [pkg/cmd/extension/git.go:58](pkg/cmd/extension/git.go#L58) - `(gitExecuter).Remotes`
- Entrypoint: gh extension git
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a PR branch or tag named `--upload-pack=touch /tmp/pwn`.
- Invariant to test: Ref values are validated against git's ref format and always follow `--`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test with hostile ref names asserting rejection or correct positioning.
