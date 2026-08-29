# Q2960: active via borrow: route a victim's mandatory payout through a principal that

## Question
Does `borrow` (mainnet/contracts/market/v0-4-market.clar:1238) let an unprivileged attacker who controls the future mask produced by the new debt bit reach `active` (mainnet/contracts/registry/v0-egroup.clar:238) in a state where it route a victim's mandatory payout through a principal that always rejects delivery? Given that it lists candidate bucket masks at or above a population, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is permanent freezing of unclaimed yield.

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:238` -> `active`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: the future mask produced by the new debt bit
- Exploit idea: `active` lists candidate bucket masks at or above a population. Reach it through `borrow` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: High - permanent freezing of unclaimed yield
- Fast validation: Write a Clarinet simnet test calling `borrow` twice with the future mask produced by the new debt bit varied, and assert that the value `active` returns is identical in both runs; a divergence confirms the finding.
