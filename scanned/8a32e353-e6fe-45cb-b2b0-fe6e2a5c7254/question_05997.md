Q5997: public fee-collection leakage in extension configuration gate when both protocol and admin fees are non-zero from the first block of pool life

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `priceProvider`, `priceProviderTimelock`, and immutable-vs-mutable provider mode selection while both protocol and admin fees are non-zero from the first block of pool life, so that a public caller can time fee collection against a state transition that causes the pool to pay out more than accumulated fees along `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance`, corrupting which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled? This gate decides whether a public pool creation request really wires every declared extension into the correct hook slots. Collect fees immediately after a live trade or liquidity transition and see whether surplus, protocol fees, and LP balances desynchronize.

Target
- File/function: metric-core/contracts/libraries/ValidateExtensionsConfig.sol::validateExtensionsConfig
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `priceProvider`, `priceProviderTimelock`, and immutable-vs-mutable provider mode selection
- Exploit idea: Reach `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance` in a live public flow and show that collect fees immediately after a live trade or liquidity transition and see whether surplus, protocol fees, and lp balances desynchronize. The exact value at risk is which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Invariant to test: Public fee collection must extract only already-accrued fees and must never touch LP-owned principal. The concrete assertion should cover which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Expected Immunefi impact: High direct protocol or LP loss if public callers can trigger over-collection.
- Fast validation: Create pools with duplicate, sparse, and reordered extension orders and assert no reachable configuration can skip a required hook while still deploying successfully.
