# Q1322: vault-accrue via liquidate-multi: write a stranger's ledger through an unsolicited on-behalf

## Question
Entering through `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593) while controlling which borrowers are placed early versus late in the batch, can an unprivileged attacker make `vault-accrue` (mainnet/contracts/market/v0-4-market.clar:189) write a stranger's ledger through an unsolicited on-behalf-of call? `vault-accrue` dispatches accrual to one of six vaults by asset id, so the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created would fail, yielding protocol insolvency.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:189` -> `vault-accrue`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: which borrowers are placed early versus late in the batch
- Exploit idea: `vault-accrue` dispatches accrual to one of six vaults by asset id. Reach it through `liquidate-multi` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `liquidate-multi` twice with which borrowers are placed early versus late in the batch varied, and assert that the value `vault-accrue` returns is identical in both runs; a divergence confirms the finding.
