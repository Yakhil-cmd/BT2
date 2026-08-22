# Q1581: missing timeout enables hang - (Client).AddRemote in client.go

## Question
Does the request path in `AddRemote` in [git/client.go](git/client.go#L831) run without a timeout/context deadline so an attacker-controlled endpoint can hang the victim's gh indefinitely (including in CI)?

## Target
- File/function: [git/client.go:831](git/client.go#L831) - `(Client).AddRemote`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Serve a slow-loris response from the host the victim's gh talks to.
- Invariant to test: Every outbound request carries a bounded timeout.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a stalling server asserting the call returns within the deadline.
