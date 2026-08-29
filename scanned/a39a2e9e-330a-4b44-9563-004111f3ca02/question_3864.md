# Q3864: total-debt via accrue: prime shared state so the next caller in the block is eval

## Question
Does `accrue` (mainnet/contracts/vault/v0-vault-stx.clar:835) let an unprivileged attacker who controls whether an earlier call in the same block already advanced last-update reach `total-debt` (mainnet/contracts/vault/v0-vault-stx.clar:328) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it computes cumulative debt from `principal-scaled` and `index`, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:328` -> `total-debt`
- Entrypoint: `accrue` (`mainnet/contracts/vault/v0-vault-stx.clar:835`), unprivileged and publicly callable
- Attacker controls: whether an earlier call in the same block already advanced last-update
- Exploit idea: `total-debt` computes cumulative debt from `principal-scaled` and `index`. Reach it through `accrue` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz whether an earlier call in the same block already advanced last-update across its boundary values through `accrue` in simnet and assert `total-debt` never returns a value that breaks the invariant.
