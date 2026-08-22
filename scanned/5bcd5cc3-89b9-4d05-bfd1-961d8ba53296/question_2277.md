# Q2277: token leaked into child env/argv - (Client).Command in client.go

## Question
Does `Command` in [git/client.go](git/client.go#L77) pass the active GitHub token via argv or an inherited environment into a process whose identity is influenced by a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes?

## Target
- File/function: [git/client.go:77](git/client.go#L77) - `(Client).Command`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Get gh to spawn a helper for an attacker-controlled host/extension and read the token from its own environment or /proc argv.
- Invariant to test: The token is only passed to processes bound to the host it authenticates.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Assert the env/argv captured by a stub runner contains no token when the target host differs from the token's host.
