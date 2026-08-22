# Q4047: executable bit from archive - downloadRun in download.go

## Question
Does `downloadRun` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L142) apply the archive's stored file mode, so attacker content lands on disk already executable in a directory gh or the shell later runs?

## Target
- File/function: [pkg/cmd/release/download/download.go:142](pkg/cmd/release/download/download.go#L142) - `downloadRun`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Ship a 0755 entry whose name matches something gh or the user's PATH executes.
- Invariant to test: Modes for extracted content are forced to a safe constant, never taken from the archive.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Assert extracted files have the fixed expected mode regardless of the header.
