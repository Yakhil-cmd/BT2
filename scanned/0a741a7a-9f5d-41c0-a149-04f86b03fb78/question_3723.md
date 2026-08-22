# Q3723: URL parsed twice with different results - (Client).AddRemote in client.go

## Question
Does `AddRemote` in [git/client.go](git/client.go#L831) parse the same attacker string with two different parsers (url.Parse vs manual split vs git URL parser) so validation and use disagree?

## Target
- File/function: [git/client.go:831](git/client.go#L831) - `(Client).AddRemote`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Craft a URL that the two parsers read differently (`https://a@b/`, `ssh://`, `git@host:path`).
- Invariant to test: One parse result is computed once and reused for both the check and the action.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Differential fuzz test comparing both parsers on random URLs.
