# Q1563: attacker-chosen executable path - (Client).Command in client.go

## Question
Can `Command` in [git/client.go](git/client.go#L77) be steered into executing a binary or script path that came from remote data (a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes) rather than from a fixed, validated location?

## Target
- File/function: [git/client.go:77](git/client.go#L77) - `(Client).Command`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Serve a manifest/response whose name or path field resolves to a file the attacker also caused to be written on disk.
- Invariant to test: The executable path must come from a constant or a validated install root, never from a server response.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Unit test with a fake runner asserting the executed path is rooted under the expected directory.
