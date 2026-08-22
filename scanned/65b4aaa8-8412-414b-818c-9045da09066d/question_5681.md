# Q5681: executable bit from archive - downloadCopilot in copilot.go

## Question
Does `downloadCopilot` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L239) apply the archive's stored file mode, so attacker content lands on disk already executable in a directory gh or the shell later runs?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:239](pkg/cmd/copilot/copilot.go#L239) - `downloadCopilot`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Ship a 0755 entry whose name matches something gh or the user's PATH executes.
- Invariant to test: Modes for extracted content are forced to a safe constant, never taken from the archive.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Assert extracted files have the fixed expected mode regardless of the header.
