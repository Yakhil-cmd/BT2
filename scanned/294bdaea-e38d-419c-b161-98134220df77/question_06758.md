Q6758: registry or destination misbinding in deployer parameter binding when both protocol and admin fees are non-zero from the first block of pool life

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while both protocol and admin fees are non-zero from the first block of pool life, so that the pool is validly created but later registry lookups or fee destinations point at the wrong address along `createPool -> MetricOmmPoolDeployer.deploy -> MetricOmmPool constructor argument binding`, corrupting the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters? The permissionless caller never touches the constructor directly, so any mismatch between factory intent and deployer binding is a deployment-time exploit surface. Cause the factory to store an address relationship that does not match the deployed pool's real control or fee sinks.

Target
- File/function: metric-core/contracts/MetricOmmPoolDeployer.sol::deploy
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> MetricOmmPoolDeployer.deploy -> MetricOmmPool constructor argument binding` in a live public flow and show that cause the factory to store an address relationship that does not match the deployed pool's real control or fee sinks. The exact value at risk is the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters.
- Invariant to test: Every address the factory later exposes as canonical metadata must belong to the same exact pool instance that was just deployed. The concrete assertion should cover the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters.
- Expected Immunefi impact: High direct loss if fees or governance-sensitive lookups are redirected to the wrong sink.
- Fast validation: Compare the factory's stored post-deploy metadata with the pool immutables and emitted `PoolCreated` event for every public creation variant.
