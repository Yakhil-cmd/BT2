# Q2826: Windows argument re-splitting - findCopilotBinary in copilot.go

## Question
On Windows, does the command assembled in `findCopilotBinary` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L225) re-split an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes because of quotes, `^`, or `&` characters passed through cmd.exe or a .bat shim?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:225](pkg/cmd/copilot/copilot.go#L225) - `findCopilotBinary`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a name containing `" & calc &` and let the victim on Windows run gh copilot copilot.
- Invariant to test: Arguments must survive Windows quoting rules unchanged; no cmd.exe interpretation of remote data.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Windows-tagged unit test asserting the escaped argument round-trips to the exact original string.
