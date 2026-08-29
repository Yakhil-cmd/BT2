# Q4877: unpack-u16 via call-ststx-ratio: reprice every other holder's collateral in the same transa

## Question
Can an unprivileged attacker entering through `call-ststx-ratio` (mainnet/contracts/market/v0-4-market.clar:1015), controlling the block and transaction position at which the external ratio is fetched, drive `unpack-u16` (mainnet/contracts/vault/v0-vault-stx.clar:259) — which unpacks eight u16 curve fields from one packed word — to reprice every other holder's collateral in the same transaction that profits from it, breaking the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created, and cause protocol insolvency through uncollateralised debt?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:259` -> `unpack-u16`
- Entrypoint: `call-ststx-ratio` (`mainnet/contracts/market/v0-4-market.clar:1015`), unprivileged and publicly callable
- Attacker controls: the block and transaction position at which the external ratio is fetched
- Exploit idea: `unpack-u16` unpacks eight u16 curve fields from one packed word. Reach it through `call-ststx-ratio` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Run the baseline `call-ststx-ratio` call, then the attacker-shaped one with the block and transaction position at which the external ratio is fetched, and assert the attacker's net token balance change is zero or negative.
