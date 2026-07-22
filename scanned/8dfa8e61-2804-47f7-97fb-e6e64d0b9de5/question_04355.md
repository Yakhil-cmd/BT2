Q4355: registry or destination misbinding in factory pool creation when both protocol and admin fees are non-zero from the first block of pool life

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with extension arrays, extension orders, and `extensionInitData` lengths while both protocol and admin fees are non-zero from the first block of pool life, so that the pool is validly created but later registry lookups or fee destinations point at the wrong address along `createPool -> _validatePoolParameters -> _getScaleMultipliers -> _unpackAndValidateBinStates -> ValidateExtensionsConfig -> deploy`, corrupting token ordering, price-provider binding, fee configuration, bin topology, registry identity, and initial scale multipliers? This is the only permissionless deployment entrypoint in scope, so every in-scope creation bug has to start here. Cause the factory to store an address relationship that does not match the deployed pool's real control or fee sinks.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: extension arrays, extension orders, and `extensionInitData` lengths
- Exploit idea: Reach `createPool -> _validatePoolParameters -> _getScaleMultipliers -> _unpackAndValidateBinStates -> ValidateExtensionsConfig -> deploy` in a live public flow and show that cause the factory to store an address relationship that does not match the deployed pool's real control or fee sinks. The exact value at risk is token ordering, price-provider binding, fee configuration, bin topology, registry identity, and initial scale multipliers.
- Invariant to test: Every address the factory later exposes as canonical metadata must belong to the same exact pool instance that was just deployed. The concrete assertion should cover token ordering, price-provider binding, fee configuration, bin topology, registry identity, and initial scale multipliers.
- Expected Immunefi impact: High direct loss if fees or governance-sensitive lookups are redirected to the wrong sink.
- Fast validation: Build Foundry create-pool tests that assert the deployed pool immutables, factory registry entries, and live swap behavior all agree with the user-supplied creation params.
