# Q2798: interest-rate via liquidate-multi: push a third party's position past a fold bound so every e

## Question
Entering through `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593) while controlling the trait principals supplied per entry, can an unprivileged attacker make `interest-rate` (mainnet/contracts/vault/v0-vault-stx.clar:371) push a third party's position past a fold bound so every evaluation of it aborts? `interest-rate` interpolates the packed curve at the current utilization, so the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends would fail, yielding permanent freezing of unclaimed yield.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:371` -> `interest-rate`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the trait principals supplied per entry
- Exploit idea: `interest-rate` interpolates the packed curve at the current utilization. Reach it through `liquidate-multi` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: High - permanent freezing of unclaimed yield
- Fast validation: Write a Clarinet simnet test calling `liquidate-multi` twice with the trait principals supplied per entry varied, and assert that the value `interest-rate` returns is identical in both runs; a divergence confirms the finding.
