# Q1609: receive-underlying via collateral-remove-redeem: write a stranger's ledger through an unsolicited on-behalf

## Question
Can an unprivileged attacker entering through `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211), controlling remaining zToken collateral whose price moves with the redeem, drive `receive-underlying` (mainnet/contracts/vault/v0-vault-stx.clar:291) — which pulls the underlying from a named account — to write a stranger's ledger through an unsolicited on-behalf-of call, breaking the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment, and cause theft of unclaimed yield?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:291` -> `receive-underlying`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: remaining zToken collateral whose price moves with the redeem
- Exploit idea: `receive-underlying` pulls the underlying from a named account. Reach it through `collateral-remove-redeem` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: In `local-testing/tests` on a local fork, drive `collateral-remove-redeem` with remaining zToken collateral whose price moves with the redeem, then read `receive-underlying` state before and after in the same block and assert the two sides of the invariant are equal.
