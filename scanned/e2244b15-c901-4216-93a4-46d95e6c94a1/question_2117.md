# Q2117: population via collateral-add: route a victim's mandatory payout through a principal that

## Question
Can an unprivileged attacker entering through `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020), controlling the `ft` trait principal, drive `population` (mainnet/contracts/registry/v0-egroup.clar:81) — which counts set bits to order the bucket search — to route a victim's mandatory payout through a principal that always rejects delivery, breaking the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more, and cause protocol insolvency?

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:81` -> `population`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `population` counts set bits to order the bucket search. Reach it through `collateral-add` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Run the baseline `collateral-add` call, then the attacker-shaped one with the `ft` trait principal, and assert the attacker's net token balance change is zero or negative.
