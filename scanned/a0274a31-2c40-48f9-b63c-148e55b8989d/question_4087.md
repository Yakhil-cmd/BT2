# Q4087: gist/file content written into the working tree - viewRun in view.go

## Question
Does `viewRun` in [pkg/cmd/gist/view/view.go](pkg/cmd/gist/view/view.go#L81) write attacker-authored file content into the victim's repository or working directory in a location git or a tool will later execute (hooks, CI config, scripts)?

## Target
- File/function: [pkg/cmd/gist/view/view.go:81](pkg/cmd/gist/view/view.go#L81) - `viewRun`
- Entrypoint: gh gist view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a gist/file whose target path is a hook or workflow file.
- Invariant to test: Writes are confined to the explicitly chosen output location.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting no write lands in .git/ or .github/.
