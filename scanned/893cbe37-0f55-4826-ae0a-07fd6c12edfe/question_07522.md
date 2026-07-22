Q7522: registry or destination misbinding in fee-collection path when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees` with mixed-decimal token pairs and initial per-share amounts near scaling boundaries while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that the pool is validly created but later registry lookups or fee destinations point at the wrong address along `collectPoolFees -> pool.collectFees -> fee split between protocol and admin destinations`, corrupting surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency? This is a public callable path, so even a non-admin can time fee collection against active state transitions if accounting is fragile. Cause the factory to store an address relationship that does not match the deployed pool's real control or fee sinks.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees -> metric-core/contracts/MetricOmmPool.sol::collectFees
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees
- Attacker controls: mixed-decimal token pairs and initial per-share amounts near scaling boundaries
- Exploit idea: Reach `collectPoolFees -> pool.collectFees -> fee split between protocol and admin destinations` in a live public flow and show that cause the factory to store an address relationship that does not match the deployed pool's real control or fee sinks. The exact value at risk is surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency.
- Invariant to test: Every address the factory later exposes as canonical metadata must belong to the same exact pool instance that was just deployed. The concrete assertion should cover surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency.
- Expected Immunefi impact: High direct loss if fees or governance-sensitive lookups are redirected to the wrong sink.
- Fast validation: Trigger swaps and liquidity changes around public fee collection and assert every collected token matches accumulated fee state without touching LP principal.
