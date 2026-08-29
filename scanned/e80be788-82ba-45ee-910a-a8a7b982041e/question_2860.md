# Q2860: interest-rate via redeem: prime shared state so the next caller in the block is eval

## Question
Does `redeem` (mainnet/contracts/vault/v0-vault-stx.clar:797) let an unprivileged attacker who controls `min-out` reach `interest-rate` (mainnet/contracts/vault/v0-vault-stx.clar:371) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it interpolates the packed curve at the current utilization, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is theft of unclaimed yield.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:371` -> `interest-rate`
- Entrypoint: `redeem` (`mainnet/contracts/vault/v0-vault-stx.clar:797`), unprivileged and publicly callable
- Attacker controls: `min-out`
- Exploit idea: `interest-rate` interpolates the packed curve at the current utilization. Reach it through `redeem` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: Set up the position in simnet, call `redeem` with `min-out`, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
