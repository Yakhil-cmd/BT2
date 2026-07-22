Q6463: scale overflow or truncation in deployer parameter binding when the packed bin arrays sit near the documented 128-entry safety boundary

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with repeated public pool-creation attempts that reuse salts, tokens, or provider identities while the packed bin arrays sit near the documented 128-entry safety boundary, so that decimal-driven scaling is accepted at creation time but later breaks native/scaled conservation along `createPool -> MetricOmmPoolDeployer.deploy -> MetricOmmPool constructor argument binding`, corrupting the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters? The permissionless caller never touches the constructor directly, so any mismatch between factory intent and deployer binding is a deployment-time exploit surface. Use a valid standard-token decimal combination and creation payload that pushes initial scaled state into a boundary the runtime math treats differently.

Target
- File/function: metric-core/contracts/MetricOmmPoolDeployer.sol::deploy
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: repeated public pool-creation attempts that reuse salts, tokens, or provider identities
- Exploit idea: Reach `createPool -> MetricOmmPoolDeployer.deploy -> MetricOmmPool constructor argument binding` in a live public flow and show that use a valid standard-token decimal combination and creation payload that pushes initial scaled state into a boundary the runtime math treats differently. The exact value at risk is the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters.
- Invariant to test: The factory must only deploy pools whose scale multipliers keep all later native/scaled conversions safe and exact within the documented rounding rules. The concrete assertion should cover the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters.
- Expected Immunefi impact: High direct loss or insolvency once live users swap or add liquidity to the malformed pool.
- Fast validation: Compare the factory's stored post-deploy metadata with the pool immutables and emitted `PoolCreated` event for every public creation variant.
