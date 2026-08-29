# Q1008: accrue-user-collateral via collateral-add: route a victim's mandatory payout through a principal that

## Question
Does `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020) let an unprivileged attacker who controls the `ft` trait principal reach `accrue-user-collateral` (mainnet/contracts/market/v0-4-market.clar:270) in a state where it route a victim's mandatory payout through a principal that always rejects delivery? Given that it accrues only rows that `is-ztoken` recognises, skipping everything else, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:270` -> `accrue-user-collateral`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `accrue-user-collateral` accrues only rows that `is-ztoken` recognises, skipping everything else. Reach it through `collateral-add` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz the `ft` trait principal across its boundary values through `collateral-add` in simnet and assert `accrue-user-collateral` never returns a value that breaks the invariant.
