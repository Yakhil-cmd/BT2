# Q2074: attacker-chosen executable path - (App).printOpenSSHConfig in ssh.go

## Question
Can `printOpenSSHConfig` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L552) be steered into executing a binary or script path that came from remote data (codespace/API response fields and everything the codespace-side process sends back) rather than from a fixed, validated location?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:552](pkg/cmd/codespace/ssh.go#L552) - `(App).printOpenSSHConfig`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Serve a manifest/response whose name or path field resolves to a file the attacker also caused to be written on disk.
- Invariant to test: The executable path must come from a constant or a validated install root, never from a server response.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Unit test with a fake runner asserting the executed path is rooted under the expected directory.
