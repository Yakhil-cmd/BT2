# Q4419: Windows argument re-splitting - (Client).Command in client.go

## Question
On Windows, does the command assembled in `Command` in [git/client.go](git/client.go#L77) re-split a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes because of quotes, `^`, or `&` characters passed through cmd.exe or a .bat shim?

## Target
- File/function: [git/client.go:77](git/client.go#L77) - `(Client).Command`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a name containing `" & calc &` and let the victim on Windows run gh repo clone.
- Invariant to test: Arguments must survive Windows quoting rules unchanged; no cmd.exe interpretation of remote data.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Windows-tagged unit test asserting the escaped argument round-trips to the exact original string.
