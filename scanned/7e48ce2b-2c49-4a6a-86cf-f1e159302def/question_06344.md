Q6344: registry or destination misbinding in extension initialization calls when the packed bin arrays sit near the documented 128-entry safety boundary

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with public `collectPoolFees` timing while a pool has fresh surplus or just crossed bins while the packed bin arrays sit near the documented 128-entry safety boundary, so that the pool is validly created but later registry lookups or fee destinations point at the wrong address along `createPool -> deploy -> extension initialize loop -> per-extension state activation`, corrupting extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections? A public creator can choose many extension combinations, so partial-init or wrong-pool initialization must fail closed. Cause the factory to store an address relationship that does not match the deployed pool's real control or fee sinks.

Target
- File/function: metric-core/contracts/libraries/CallExtension.sol::callExtension and metric-periphery/contracts/extensions/base/BaseMetricExtension.sol::initialize
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: public `collectPoolFees` timing while a pool has fresh surplus or just crossed bins
- Exploit idea: Reach `createPool -> deploy -> extension initialize loop -> per-extension state activation` in a live public flow and show that cause the factory to store an address relationship that does not match the deployed pool's real control or fee sinks. The exact value at risk is extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Invariant to test: Every address the factory later exposes as canonical metadata must belong to the same exact pool instance that was just deployed. The concrete assertion should cover extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Expected Immunefi impact: High direct loss if fees or governance-sensitive lookups are redirected to the wrong sink.
- Fast validation: Deploy pools with multiple extensions and assert every extension either initializes fully for that pool or causes the whole creation flow to revert.
