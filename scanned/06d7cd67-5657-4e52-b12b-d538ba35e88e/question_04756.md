Q4756: registry or destination misbinding in pool-parameter validation when both protocol and admin fees are non-zero from the first block of pool life

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `adminSpreadFeeE6`, `adminNotionalFeeE8`, and `adminFeeDestination` values that appear within documented caps while both protocol and admin fees are non-zero from the first block of pool life, so that the pool is validly created but later registry lookups or fee destinations point at the wrong address along `createPool -> _validatePoolParameters -> deploy-time state binding`, corrupting the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions? Any validation gap here lets a fully public caller mint a pool shape the rest of the system later trusts as safe. Cause the factory to store an address relationship that does not match the deployed pool's real control or fee sinks.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_validatePoolParameters
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `adminSpreadFeeE6`, `adminNotionalFeeE8`, and `adminFeeDestination` values that appear within documented caps
- Exploit idea: Reach `createPool -> _validatePoolParameters -> deploy-time state binding` in a live public flow and show that cause the factory to store an address relationship that does not match the deployed pool's real control or fee sinks. The exact value at risk is the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Invariant to test: Every address the factory later exposes as canonical metadata must belong to the same exact pool instance that was just deployed. The concrete assertion should cover the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Expected Immunefi impact: High direct loss if fees or governance-sensitive lookups are redirected to the wrong sink.
- Fast validation: Generate malformed but standard-ERC20 pool configs and assert every one that would later break swap/liquidity safety is rejected before deployment.
