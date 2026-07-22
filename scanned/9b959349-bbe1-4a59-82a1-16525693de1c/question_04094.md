Q4094: bin-topology confusion in factory pool creation when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while the bin arrays populate only one side of the curve or leave one side empty, so that packed bin data decodes into a live curve different from the one that validation or events implied along `createPool -> _validatePoolParameters -> _getScaleMultipliers -> _unpackAndValidateBinStates -> ValidateExtensionsConfig -> deploy`, corrupting token ordering, price-provider binding, fee configuration, bin topology, registry identity, and initial scale multipliers? This is the only permissionless deployment entrypoint in scope, so every in-scope creation bug has to start here. Build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> _validatePoolParameters -> _getScaleMultipliers -> _unpackAndValidateBinStates -> ValidateExtensionsConfig -> deploy` in a live public flow and show that build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended. The exact value at risk is token ordering, price-provider binding, fee configuration, bin topology, registry identity, and initial scale multipliers.
- Invariant to test: The live deployed bin topology must match the validated and emitted packed configuration exactly. The concrete assertion should cover token ordering, price-provider binding, fee configuration, bin topology, registry identity, and initial scale multipliers.
- Expected Immunefi impact: High bad-price execution or LP fund loss once the public pool goes live.
- Fast validation: Build Foundry create-pool tests that assert the deployed pool immutables, factory registry entries, and live swap behavior all agree with the user-supplied creation params.
