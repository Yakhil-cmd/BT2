Q5803: identity collision in extension configuration gate when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with extension arrays, extension orders, and `extensionInitData` lengths while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that public creation attempts can make canonical pool identity ambiguous for routers, providers, or state readers along `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance`, corrupting which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled? This gate decides whether a public pool creation request really wires every declared extension into the correct hook slots. Reuse salts, providers, or equivalent metadata to see whether the factory or deployer treats two distinct pools as the same canonical instance.

Target
- File/function: metric-core/contracts/libraries/ValidateExtensionsConfig.sol::validateExtensionsConfig
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: extension arrays, extension orders, and `extensionInitData` lengths
- Exploit idea: Reach `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance` in a live public flow and show that reuse salts, providers, or equivalent metadata to see whether the factory or deployer treats two distinct pools as the same canonical instance. The exact value at risk is which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Invariant to test: Every public pool creation must either revert or register a unique canonical identity consumed consistently across the stack. The concrete assertion should cover which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Expected Immunefi impact: High if integrations or price providers can be tricked into routing value to the wrong pool.
- Fast validation: Create pools with duplicate, sparse, and reordered extension orders and assert no reachable configuration can skip a required hook while still deploying successfully.
