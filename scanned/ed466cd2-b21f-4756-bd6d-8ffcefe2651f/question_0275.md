# Q0275: calc-liq-debt-repay via liquidate: seize from a position that is solvent under the mask its o

## Question
`calc-liq-debt-repay` (mainnet/contracts/market/v0-4-market.clar:723) takes the liquidation factor times the debt with `mul-bps-down`. Can an unprivileged caller of `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382), by choosing which collateral and debt asset pair is targeted, use that to seize from a position that is solvent under the mask its own operations were validated against, violating the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements and producing protocol insolvency through uncollateralised debt?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:723` -> `calc-liq-debt-repay`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: which collateral and debt asset pair is targeted
- Exploit idea: `calc-liq-debt-repay` takes the liquidation factor times the debt with `mul-bps-down`. Reach it through `liquidate` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Run the baseline `liquidate` call, then the attacker-shaped one with which collateral and debt asset pair is targeted, and assert the attacker's net token balance change is zero or negative.
