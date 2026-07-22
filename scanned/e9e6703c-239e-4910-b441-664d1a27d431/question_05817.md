Q5817: identity collision in extension configuration gate when the packed bin arrays sit near the documented 128-entry safety boundary

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with permissionless `createPool` calldata for token ordering, salt, and initial bin arrays while the packed bin arrays sit near the documented 128-entry safety boundary, so that public creation attempts can make canonical pool identity ambiguous for routers, providers, or state readers along `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance`, corrupting which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled? This gate decides whether a public pool creation request really wires every declared extension into the correct hook slots. Reuse salts, providers, or equivalent metadata to see whether the factory or deployer treats two distinct pools as the same canonical instance.

Target
- File/function: metric-core/contracts/libraries/ValidateExtensionsConfig.sol::validateExtensionsConfig
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: permissionless `createPool` calldata for token ordering, salt, and initial bin arrays
- Exploit idea: Reach `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance` in a live public flow and show that reuse salts, providers, or equivalent metadata to see whether the factory or deployer treats two distinct pools as the same canonical instance. The exact value at risk is which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Invariant to test: Every public pool creation must either revert or register a unique canonical identity consumed consistently across the stack. The concrete assertion should cover which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Expected Immunefi impact: High if integrations or price providers can be tricked into routing value to the wrong pool.
- Fast validation: Create pools with duplicate, sparse, and reordered extension orders and assert no reachable configuration can skip a required hook while still deploying successfully.
