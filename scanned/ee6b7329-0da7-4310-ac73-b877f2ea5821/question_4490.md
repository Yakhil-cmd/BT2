# Q4490: create via supply-collateral-add: prime shared state so the next caller in the block is eval

## Question
Entering through `supply-collateral-add` (mainnet/contracts/market/v0-4-market.clar:1175) while controlling vault share price at the moment of the deposit leg, can an unprivileged attacker make `create` (mainnet/contracts/market/v0-market-vault.clar:150) prime shared state so the next caller in the block is evaluated against it? `create` binds a principal to a fresh numeric id, so the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment would fail, yielding permanent freezing of unclaimed yield.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:150` -> `create`
- Entrypoint: `supply-collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1175`), unprivileged and publicly callable
- Attacker controls: vault share price at the moment of the deposit leg
- Exploit idea: `create` binds a principal to a fresh numeric id. Reach it through `supply-collateral-add` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: High - permanent freezing of unclaimed yield
- Fast validation: Write a Clarinet simnet test calling `supply-collateral-add` twice with vault share price at the moment of the deposit leg varied, and assert that the value `create` returns is identical in both runs; a divergence confirms the finding.
