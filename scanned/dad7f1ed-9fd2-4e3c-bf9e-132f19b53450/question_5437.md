# Q5437: calc-cumulative-debt via supply-collateral-add: route a victim's mandatory payout through a principal that

## Question
Can an unprivileged attacker entering through `supply-collateral-add` (mainnet/contracts/market/v0-4-market.clar:1175), controlling `min-shares` (the only slippage bound on the deposit leg), drive `calc-cumulative-debt` (mainnet/contracts/vault/v0-vault-stx.clar:180) — which multiplies scaled principal by an index — to route a victim's mandatory payout through a principal that always rejects delivery, breaking the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends, and cause direct theft of user funds at rest or in motion?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:180` -> `calc-cumulative-debt`
- Entrypoint: `supply-collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1175`), unprivileged and publicly callable
- Attacker controls: `min-shares` (the only slippage bound on the deposit leg)
- Exploit idea: `calc-cumulative-debt` multiplies scaled principal by an index. Reach it through `supply-collateral-add` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: In `local-testing/tests` on a local fork, drive `supply-collateral-add` with `min-shares` (the only slippage bound on the deposit leg), then read `calc-cumulative-debt` state before and after in the same block and assert the two sides of the invariant are equal.
