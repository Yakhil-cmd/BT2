# Q5919: ref name starting with a dash - RepoNameFromRemote in registry.go

## Question
Does `RepoNameFromRemote` in [internal/skills/registry/registry.go](internal/skills/registry/registry.go#L447) place a branch/ref/tag name from remote data in a git argv position where a leading `-` becomes an option (e.g. `--upload-pack=`)?

## Target
- File/function: [internal/skills/registry/registry.go:447](internal/skills/registry/registry.go#L447) - `RepoNameFromRemote`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a PR branch or tag named `--upload-pack=touch /tmp/pwn`.
- Invariant to test: Ref values are validated against git's ref format and always follow `--`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test with hostile ref names asserting rejection or correct positioning.
