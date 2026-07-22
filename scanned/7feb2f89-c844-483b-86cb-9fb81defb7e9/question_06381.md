Q6381: public fee-collection leakage in extension initialization calls when the packed bin arrays sit near the documented 128-entry safety boundary

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `priceProvider`, `priceProviderTimelock`, and immutable-vs-mutable provider mode selection while the packed bin arrays sit near the documented 128-entry safety boundary, so that a public caller can time fee collection against a state transition that causes the pool to pay out more than accumulated fees along `createPool -> deploy -> extension initialize loop -> per-extension state activation`, corrupting extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections? A public creator can choose many extension combinations, so partial-init or wrong-pool initialization must fail closed. Collect fees immediately after a live trade or liquidity transition and see whether surplus, protocol fees, and LP balances desynchronize.

Target
- File/function: metric-core/contracts/libraries/CallExtension.sol::callExtension and metric-periphery/contracts/extensions/base/BaseMetricExtension.sol::initialize
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `priceProvider`, `priceProviderTimelock`, and immutable-vs-mutable provider mode selection
- Exploit idea: Reach `createPool -> deploy -> extension initialize loop -> per-extension state activation` in a live public flow and show that collect fees immediately after a live trade or liquidity transition and see whether surplus, protocol fees, and lp balances desynchronize. The exact value at risk is extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Invariant to test: Public fee collection must extract only already-accrued fees and must never touch LP-owned principal. The concrete assertion should cover extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Expected Immunefi impact: High direct protocol or LP loss if public callers can trigger over-collection.
- Fast validation: Deploy pools with multiple extensions and assert every extension either initializes fully for that pool or causes the whole creation flow to revert.
