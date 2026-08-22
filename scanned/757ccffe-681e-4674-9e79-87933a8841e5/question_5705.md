# Q5705: attacker-chosen executable path - (Context).findKeygen in ssh_keys.go

## Question
Can `findKeygen` in [pkg/ssh/ssh_keys.go](pkg/ssh/ssh_keys.go#L102) be steered into executing a binary or script path that came from remote data (an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes) rather than from a fixed, validated location?

## Target
- File/function: [pkg/ssh/ssh_keys.go:102](pkg/ssh/ssh_keys.go#L102) - `(Context).findKeygen`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Serve a manifest/response whose name or path field resolves to a file the attacker also caused to be written on disk.
- Invariant to test: The executable path must come from a constant or a validated install root, never from a server response.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Unit test with a fake runner asserting the executed path is rooted under the expected directory.
