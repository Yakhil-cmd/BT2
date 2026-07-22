Q5921: registry or destination misbinding in extension configuration gate when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with permissionless `createPool` calldata for token ordering, salt, and initial bin arrays while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that the pool is validly created but later registry lookups or fee destinations point at the wrong address along `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance`, corrupting which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled? This gate decides whether a public pool creation request really wires every declared extension into the correct hook slots. Cause the factory to store an address relationship that does not match the deployed pool's real control or fee sinks.

Target
- File/function: metric-core/contracts/libraries/ValidateExtensionsConfig.sol::validateExtensionsConfig
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: permissionless `createPool` calldata for token ordering, salt, and initial bin arrays
- Exploit idea: Reach `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance` in a live public flow and show that cause the factory to store an address relationship that does not match the deployed pool's real control or fee sinks. The exact value at risk is which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Invariant to test: Every address the factory later exposes as canonical metadata must belong to the same exact pool instance that was just deployed. The concrete assertion should cover which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Expected Immunefi impact: High direct loss if fees or governance-sensitive lookups are redirected to the wrong sink.
- Fast validation: Create pools with duplicate, sparse, and reordered extension orders and assert no reachable configuration can skip a required hook while still deploying successfully.
