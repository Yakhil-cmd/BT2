# Q4085: gist/file content written into the working tree - getFilesToAdd in edit.go

## Question
Does `getFilesToAdd` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L420) write attacker-authored file content into the victim's repository or working directory in a location git or a tool will later execute (hooks, CI config, scripts)?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:420](pkg/cmd/gist/edit/edit.go#L420) - `getFilesToAdd`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a gist/file whose target path is a hook or workflow file.
- Invariant to test: Writes are confined to the explicitly chosen output location.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting no write lands in .git/ or .github/.
