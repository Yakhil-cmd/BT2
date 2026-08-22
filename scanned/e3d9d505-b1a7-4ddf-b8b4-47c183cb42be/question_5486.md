# Q5486: executable bit from archive - newZipLogMap in logs.go

## Question
Does `newZipLogMap` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L166) apply the archive's stored file mode, so attacker content lands on disk already executable in a directory gh or the shell later runs?

## Target
- File/function: [pkg/cmd/run/view/logs.go:166](pkg/cmd/run/view/logs.go#L166) - `newZipLogMap`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Ship a 0755 entry whose name matches something gh or the user's PATH executes.
- Invariant to test: Modes for extracted content are forced to a safe constant, never taken from the archive.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Assert extracted files have the fixed expected mode regardless of the header.
