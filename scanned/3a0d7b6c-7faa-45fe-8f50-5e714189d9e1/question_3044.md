# Q3044: Windows argument re-splitting - executeCmds in checkout.go

## Question
On Windows, does the command assembled in `executeCmds` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L356) re-split a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes because of quotes, `^`, or `&` characters passed through cmd.exe or a .bat shim?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:356](pkg/cmd/pr/checkout/checkout.go#L356) - `executeCmds`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a name containing `" & calc &` and let the victim on Windows run gh pr checkout.
- Invariant to test: Arguments must survive Windows quoting rules unchanged; no cmd.exe interpretation of remote data.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Windows-tagged unit test asserting the escaped argument round-trips to the exact original string.
