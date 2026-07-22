Q5701: bin-topology confusion in extension configuration gate when the packed bin arrays sit near the documented 128-entry safety boundary

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `priceProvider`, `priceProviderTimelock`, and immutable-vs-mutable provider mode selection while the packed bin arrays sit near the documented 128-entry safety boundary, so that packed bin data decodes into a live curve different from the one that validation or events implied along `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance`, corrupting which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled? This gate decides whether a public pool creation request really wires every declared extension into the correct hook slots. Build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended.

Target
- File/function: metric-core/contracts/libraries/ValidateExtensionsConfig.sol::validateExtensionsConfig
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `priceProvider`, `priceProviderTimelock`, and immutable-vs-mutable provider mode selection
- Exploit idea: Reach `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance` in a live public flow and show that build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended. The exact value at risk is which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Invariant to test: The live deployed bin topology must match the validated and emitted packed configuration exactly. The concrete assertion should cover which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Expected Immunefi impact: High bad-price execution or LP fund loss once the public pool goes live.
- Fast validation: Create pools with duplicate, sparse, and reordered extension orders and assert no reachable configuration can skip a required hook while still deploying successfully.
