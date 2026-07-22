Q4206: identity collision in factory pool creation when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that public creation attempts can make canonical pool identity ambiguous for routers, providers, or state readers along `createPool -> _validatePoolParameters -> _getScaleMultipliers -> _unpackAndValidateBinStates -> ValidateExtensionsConfig -> deploy`, corrupting token ordering, price-provider binding, fee configuration, bin topology, registry identity, and initial scale multipliers? This is the only permissionless deployment entrypoint in scope, so every in-scope creation bug has to start here. Reuse salts, providers, or equivalent metadata to see whether the factory or deployer treats two distinct pools as the same canonical instance.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> _validatePoolParameters -> _getScaleMultipliers -> _unpackAndValidateBinStates -> ValidateExtensionsConfig -> deploy` in a live public flow and show that reuse salts, providers, or equivalent metadata to see whether the factory or deployer treats two distinct pools as the same canonical instance. The exact value at risk is token ordering, price-provider binding, fee configuration, bin topology, registry identity, and initial scale multipliers.
- Invariant to test: Every public pool creation must either revert or register a unique canonical identity consumed consistently across the stack. The concrete assertion should cover token ordering, price-provider binding, fee configuration, bin topology, registry identity, and initial scale multipliers.
- Expected Immunefi impact: High if integrations or price providers can be tricked into routing value to the wrong pool.
- Fast validation: Build Foundry create-pool tests that assert the deployed pool immutables, factory registry entries, and live swap behavior all agree with the user-supplied creation params.
