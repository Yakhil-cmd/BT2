# Q1590: sync/push targets attacker remote - (Command).Run in command.go

## Question
Can `Run` in [git/command.go](git/command.go#L19) be steered by repo metadata into pushing the victim's local branches (possibly containing private code) to a remote the attacker controls?

## Target
- File/function: [git/command.go:19](git/command.go#L19) - `(Command).Run`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose upstream/parent metadata points at the attacker.
- Invariant to test: Push targets are confirmed and host-validated.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting the push remote for hostile metadata.
