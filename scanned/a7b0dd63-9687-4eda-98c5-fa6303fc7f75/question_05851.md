Q5851: mutable-provider mode confusion in extension configuration gate when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with extension arrays, extension orders, and `extensionInitData` lengths while the bin arrays populate only one side of the curve or leave one side empty, so that the factory accepts a provider mode that runtime code interprets differently during later price-provider updates along `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance`, corrupting which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled? This gate decides whether a public pool creation request really wires every declared extension into the correct hook slots. Choose creation parameters that make the pool think its provider is immutable while factory storage later treats it as mutable, or the reverse.

Target
- File/function: metric-core/contracts/libraries/ValidateExtensionsConfig.sol::validateExtensionsConfig
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: extension arrays, extension orders, and `extensionInitData` lengths
- Exploit idea: Reach `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance` in a live public flow and show that choose creation parameters that make the pool think its provider is immutable while factory storage later treats it as mutable, or the reverse. The exact value at risk is which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Invariant to test: Provider mutability and update timelock semantics must be fixed and unambiguous from deployment onward. The concrete assertion should cover which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Expected Immunefi impact: Medium/High bad-price execution or admin-boundary break if the wrong provider can govern live swaps.
- Fast validation: Create pools with duplicate, sparse, and reordered extension orders and assert no reachable configuration can skip a required hook while still deploying successfully.
