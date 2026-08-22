# Q2336: Windows argument re-splitting - StubFinderForRunCommandStyleTests in finder.go

## Question
On Windows, does the command assembled in `StubFinderForRunCommandStyleTests` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L78) re-split a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes because of quotes, `^`, or `&` characters passed through cmd.exe or a .bat shim?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:78](pkg/cmd/pr/shared/finder.go#L78) - `StubFinderForRunCommandStyleTests`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a name containing `" & calc &` and let the victim on Windows run gh pr.
- Invariant to test: Arguments must survive Windows quoting rules unchanged; no cmd.exe interpretation of remote data.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Windows-tagged unit test asserting the escaped argument round-trips to the exact original string.
