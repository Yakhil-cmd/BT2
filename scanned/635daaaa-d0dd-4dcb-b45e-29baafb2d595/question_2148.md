# Q2148: send-underlying via transfer: reprice every other holder's collateral in the same transa

## Question
Does `transfer` (mainnet/contracts/vault/v0-vault-stx.clar:752) let an unprivileged attacker who controls `amount` reach `send-underlying` (mainnet/contracts/vault/v0-vault-stx.clar:296) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it pushes the underlying under an `as-contract?` post-condition scope, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is permanent freezing of a position that can never be closed.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:296` -> `send-underlying`
- Entrypoint: `transfer` (`mainnet/contracts/vault/v0-vault-stx.clar:752`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `send-underlying` pushes the underlying under an `as-contract?` post-condition scope. Reach it through `transfer` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Fuzz `amount` across its boundary values through `transfer` in simnet and assert `send-underlying` never returns a value that breaks the invariant.
