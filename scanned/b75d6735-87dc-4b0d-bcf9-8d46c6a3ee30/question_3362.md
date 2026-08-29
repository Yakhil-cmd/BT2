# Q3362: receive-tokens via liquidate: reprice every other holder's collateral in the same transa

## Question
Entering through `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) while controlling which collateral and debt asset pair is targeted, can an unprivileged attacker make `receive-tokens` (mainnet/contracts/market/v0-market-vault.clar:256) reprice every other holder's collateral in the same transaction that profits from it? `receive-tokens` pulls an asset from a named account, so the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements would fail, yielding protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:256` -> `receive-tokens`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: which collateral and debt asset pair is targeted
- Exploit idea: `receive-tokens` pulls an asset from a named account. Reach it through `liquidate` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `liquidate` twice with which collateral and debt asset pair is targeted varied, and assert that the value `receive-tokens` returns is identical in both runs; a divergence confirms the finding.
