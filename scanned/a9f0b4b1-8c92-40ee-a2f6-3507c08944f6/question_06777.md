Q6777: public fee-collection leakage in deployer parameter binding when the packed bin arrays sit near the documented 128-entry safety boundary

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with permissionless `createPool` calldata for token ordering, salt, and initial bin arrays while the packed bin arrays sit near the documented 128-entry safety boundary, so that a public caller can time fee collection against a state transition that causes the pool to pay out more than accumulated fees along `createPool -> MetricOmmPoolDeployer.deploy -> MetricOmmPool constructor argument binding`, corrupting the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters? The permissionless caller never touches the constructor directly, so any mismatch between factory intent and deployer binding is a deployment-time exploit surface. Collect fees immediately after a live trade or liquidity transition and see whether surplus, protocol fees, and LP balances desynchronize.

Target
- File/function: metric-core/contracts/MetricOmmPoolDeployer.sol::deploy
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: permissionless `createPool` calldata for token ordering, salt, and initial bin arrays
- Exploit idea: Reach `createPool -> MetricOmmPoolDeployer.deploy -> MetricOmmPool constructor argument binding` in a live public flow and show that collect fees immediately after a live trade or liquidity transition and see whether surplus, protocol fees, and lp balances desynchronize. The exact value at risk is the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters.
- Invariant to test: Public fee collection must extract only already-accrued fees and must never touch LP-owned principal. The concrete assertion should cover the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters.
- Expected Immunefi impact: High direct protocol or LP loss if public callers can trigger over-collection.
- Fast validation: Compare the factory's stored post-deploy metadata with the pool immutables and emitted `PoolCreated` event for every public creation variant.
