Q6566: partial initialization in deployer parameter binding when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that one extension is initialized with live pool state while another fails or binds to the wrong pool along `createPool -> MetricOmmPoolDeployer.deploy -> MetricOmmPool constructor argument binding`, corrupting the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters? The permissionless caller never touches the constructor directly, so any mismatch between factory intent and deployer binding is a deployment-time exploit surface. Use a public creation payload that leaves the pool only partially protected but still accepted by the factory and registry.

Target
- File/function: metric-core/contracts/MetricOmmPoolDeployer.sol::deploy
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> MetricOmmPoolDeployer.deploy -> MetricOmmPool constructor argument binding` in a live public flow and show that use a public creation payload that leaves the pool only partially protected but still accepted by the factory and registry. The exact value at risk is the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters.
- Invariant to test: Pool creation must be atomic across deploy plus extension initialization; partial protection is not a safe deployed state. The concrete assertion should cover the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters.
- Expected Immunefi impact: High direct user or LP loss when later public actions rely on a half-initialized extension set.
- Fast validation: Compare the factory's stored post-deploy metadata with the pool immutables and emitted `PoolCreated` event for every public creation variant.
