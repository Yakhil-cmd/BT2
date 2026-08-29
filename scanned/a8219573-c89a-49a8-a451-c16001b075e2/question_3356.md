# Q3356: calc-multiplier-delta via liquidate-multi: make a victim's position resolve to a worse efficiency gro

## Question
Does `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593) let an unprivileged attacker who controls which borrowers are placed early versus late in the batch reach `calc-multiplier-delta` (mainnet/contracts/vault/v0-vault-stx.clar:170) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it compounds a rate over `time-delta` with a caller-independent rounding flag, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:170` -> `calc-multiplier-delta`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: which borrowers are placed early versus late in the batch
- Exploit idea: `calc-multiplier-delta` compounds a rate over `time-delta` with a caller-independent rounding flag. Reach it through `liquidate-multi` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `liquidate-multi` twice with which borrowers are placed early versus late in the batch varied, and assert that the value `calc-multiplier-delta` returns is identical in both runs; a divergence confirms the finding.
