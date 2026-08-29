# Q4258: remove-user-collateral via transfer: route a victim's mandatory payout through a principal that

## Question
Entering through `transfer` (mainnet/contracts/vault/v0-vault-stx.clar:752) while controlling `amount`, can an unprivileged attacker make `remove-user-collateral` (mainnet/contracts/market/v0-market-vault.clar:205) route a victim's mandatory payout through a principal that always rejects delivery? `remove-user-collateral` asserts sufficiency then `map-delete`s only on an exact zero, so the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment would fail, yielding direct theft of user funds at rest or in motion.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:205` -> `remove-user-collateral`
- Entrypoint: `transfer` (`mainnet/contracts/vault/v0-vault-stx.clar:752`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `remove-user-collateral` asserts sufficiency then `map-delete`s only on an exact zero. Reach it through `transfer` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: Set up the position in simnet, call `transfer` with `amount`, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
