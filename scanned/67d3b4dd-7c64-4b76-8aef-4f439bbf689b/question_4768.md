# Q4768: gist/file content written into the working tree - isolateArtifacts in download.go

## Question
Does `isolateArtifacts` in [pkg/cmd/run/download/download.go](pkg/cmd/run/download/download.go#L205) write attacker-authored file content into the victim's repository or working directory in a location git or a tool will later execute (hooks, CI config, scripts)?

## Target
- File/function: [pkg/cmd/run/download/download.go:205](pkg/cmd/run/download/download.go#L205) - `isolateArtifacts`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a gist/file whose target path is a hook or workflow file.
- Invariant to test: Writes are confined to the explicitly chosen output location.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting no write lands in .git/ or .github/.
