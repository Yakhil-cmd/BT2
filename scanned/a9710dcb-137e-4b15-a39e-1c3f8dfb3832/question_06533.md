Q6533: hook-order hole in deployer parameter binding when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `priceProvider`, `priceProviderTimelock`, and immutable-vs-mutable provider mode selection while the bin arrays populate only one side of the curve or leave one side empty, so that an extension set looks enabled but a reachable order gap or duplicate causes a required hook not to run along `createPool -> MetricOmmPoolDeployer.deploy -> MetricOmmPool constructor argument binding`, corrupting the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters? The permissionless caller never touches the constructor directly, so any mismatch between factory intent and deployer binding is a deployment-time exploit surface. Deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path.

Target
- File/function: metric-core/contracts/MetricOmmPoolDeployer.sol::deploy
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `priceProvider`, `priceProviderTimelock`, and immutable-vs-mutable provider mode selection
- Exploit idea: Reach `createPool -> MetricOmmPoolDeployer.deploy -> MetricOmmPool constructor argument binding` in a live public flow and show that deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path. The exact value at risk is the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters.
- Invariant to test: Every configured hook must execute exactly as declared and in the validated order on live user flows. The concrete assertion should cover the constructor salt, token pair, provider mode, admin identity, fee destination, and immutable curve parameters.
- Expected Immunefi impact: High direct loss if an allowlist or oracle guard silently fails open on a production pool.
- Fast validation: Compare the factory's stored post-deploy metadata with the pool immutables and emitted `PoolCreated` event for every public creation variant.
