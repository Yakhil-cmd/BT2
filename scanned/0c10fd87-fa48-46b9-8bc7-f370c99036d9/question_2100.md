# Q2100: debt-preview via deposit: make a victim's position resolve to a worse efficiency gro

## Question
Does `deposit` (mainnet/contracts/vault/v0-vault-stx.clar:763) let an unprivileged attacker who controls `min-out` reach `debt-preview` (mainnet/contracts/vault/v0-vault-stx.clar:331) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it computes cumulative debt from `principal-scaled` and the FORWARD index, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:331` -> `debt-preview`
- Entrypoint: `deposit` (`mainnet/contracts/vault/v0-vault-stx.clar:763`), unprivileged and publicly callable
- Attacker controls: `min-out`
- Exploit idea: `debt-preview` computes cumulative debt from `principal-scaled` and the FORWARD index. Reach it through `deposit` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `min-out` across its boundary values through `deposit` in simnet and assert `debt-preview` never returns a value that breaks the invariant.
