Q7881: fee-cap drift in deployed fee configuration when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with permissionless `createPool` calldata for token ordering, salt, and initial bin arrays while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that publicly chosen admin-side fees remain within apparent bounds individually but aggregate unsafely when bound into live pool state along `createPool -> protocol/admin fee aggregation -> pool constructor or factory-set fee state`, corrupting `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection? A permissionless pool creator can choose admin-side fees inside the documented bounds, so aggregation has to stay exact at deployment. Pick a creation payload whose protocol-plus-admin fee aggregation lands on a runtime edge the swap path handles incorrectly.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::createPool fee aggregation and metric-core/contracts/MetricOmmPool.sol::setPoolFees
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: permissionless `createPool` calldata for token ordering, salt, and initial bin arrays
- Exploit idea: Reach `createPool -> protocol/admin fee aggregation -> pool constructor or factory-set fee state` in a live public flow and show that pick a creation payload whose protocol-plus-admin fee aggregation lands on a runtime edge the swap path handles incorrectly. The exact value at risk is `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection.
- Invariant to test: Fee caps must hold after aggregation, not merely before, and live fee state must stay within the validated envelope. The concrete assertion should cover `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection.
- Expected Immunefi impact: Medium/High fee leakage or user overcharge above contest thresholds.
- Fast validation: Create pools at and around fee boundaries and assert live swap fees plus fee-collection outputs match the configured protocol/admin split exactly.
