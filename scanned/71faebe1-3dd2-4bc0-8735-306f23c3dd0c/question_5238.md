# Q5238: vault-accrue via liquidate-multi: make a victim's position resolve to a worse efficiency gro

## Question
Entering through `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593) while controlling which borrowers are placed early versus late in the batch, can an unprivileged attacker make `vault-accrue` (mainnet/contracts/market/v0-4-market.clar:189) make a victim's position resolve to a worse efficiency group than it chose? `vault-accrue` dispatches accrual to one of six vaults by asset id, so the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more would fail, yielding temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:189` -> `vault-accrue`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: which borrowers are placed early versus late in the batch
- Exploit idea: `vault-accrue` dispatches accrual to one of six vaults by asset id. Reach it through `liquidate-multi` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz which borrowers are placed early versus late in the batch across its boundary values through `liquidate-multi` in simnet and assert `vault-accrue` never returns a value that breaks the invariant.
