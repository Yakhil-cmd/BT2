Q4155: hook-order hole in factory pool creation when both protocol and admin fees are non-zero from the first block of pool life

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with extension arrays, extension orders, and `extensionInitData` lengths while both protocol and admin fees are non-zero from the first block of pool life, so that an extension set looks enabled but a reachable order gap or duplicate causes a required hook not to run along `createPool -> _validatePoolParameters -> _getScaleMultipliers -> _unpackAndValidateBinStates -> ValidateExtensionsConfig -> deploy`, corrupting token ordering, price-provider binding, fee configuration, bin topology, registry identity, and initial scale multipliers? This is the only permissionless deployment entrypoint in scope, so every in-scope creation bug has to start here. Deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: extension arrays, extension orders, and `extensionInitData` lengths
- Exploit idea: Reach `createPool -> _validatePoolParameters -> _getScaleMultipliers -> _unpackAndValidateBinStates -> ValidateExtensionsConfig -> deploy` in a live public flow and show that deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path. The exact value at risk is token ordering, price-provider binding, fee configuration, bin topology, registry identity, and initial scale multipliers.
- Invariant to test: Every configured hook must execute exactly as declared and in the validated order on live user flows. The concrete assertion should cover token ordering, price-provider binding, fee configuration, bin topology, registry identity, and initial scale multipliers.
- Expected Immunefi impact: High direct loss if an allowlist or oracle guard silently fails open on a production pool.
- Fast validation: Build Foundry create-pool tests that assert the deployed pool immutables, factory registry entries, and live swap behavior all agree with the user-supplied creation params.
