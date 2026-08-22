# Q0867: numeric overflow / negative length - (Client).AddRemote in client.go

## Question
Does `AddRemote` in [git/client.go](git/client.go#L831) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [git/client.go:831](git/client.go#L831) - `(Client).AddRemote`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
