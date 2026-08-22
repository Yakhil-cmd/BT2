# Q1594: unbounded response body - NewRemote in objects.go

## Question
Does `NewRemote` in [git/objects.go](git/objects.go#L42) read the whole response body into memory without a limit, so an attacker-controlled endpoint can exhaust the victim's RAM?

## Target
- File/function: [git/objects.go:42](git/objects.go#L42) - `NewRemote`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Serve a multi-gigabyte body from an attacker-controlled host or asset URL.
- Invariant to test: Response reads are wrapped in a limit reader with an explicit cap.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a huge/endless body asserting a bounded error.
