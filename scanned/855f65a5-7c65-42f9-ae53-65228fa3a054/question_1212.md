# Q1212: total-assets-preview via deposit: prime shared state so the next caller in the block is eval

## Question
Does `deposit` (mainnet/contracts/vault/v0-vault-stx.clar:763) let an unprivileged attacker who controls `recipient`, including a contract principal reach `total-assets-preview` (mainnet/contracts/vault/v0-vault-stx.clar:341) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it re-derives a FORWARD index inside calls that have already accrued, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is permanent freezing of a position that can never be closed.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:341` -> `total-assets-preview`
- Entrypoint: `deposit` (`mainnet/contracts/vault/v0-vault-stx.clar:763`), unprivileged and publicly callable
- Attacker controls: `recipient`, including a contract principal
- Exploit idea: `total-assets-preview` re-derives a FORWARD index inside calls that have already accrued. Reach it through `deposit` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Fuzz `recipient`, including a contract principal across its boundary values through `deposit` in simnet and assert `total-assets-preview` never returns a value that breaks the invariant.
