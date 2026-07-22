Q7761: partial initialization in deployed fee configuration when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with permissionless `createPool` calldata for token ordering, salt, and initial bin arrays while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that one extension is initialized with live pool state while another fails or binds to the wrong pool along `createPool -> protocol/admin fee aggregation -> pool constructor or factory-set fee state`, corrupting `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection? A permissionless pool creator can choose admin-side fees inside the documented bounds, so aggregation has to stay exact at deployment. Use a public creation payload that leaves the pool only partially protected but still accepted by the factory and registry.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::createPool fee aggregation and metric-core/contracts/MetricOmmPool.sol::setPoolFees
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: permissionless `createPool` calldata for token ordering, salt, and initial bin arrays
- Exploit idea: Reach `createPool -> protocol/admin fee aggregation -> pool constructor or factory-set fee state` in a live public flow and show that use a public creation payload that leaves the pool only partially protected but still accepted by the factory and registry. The exact value at risk is `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection.
- Invariant to test: Pool creation must be atomic across deploy plus extension initialization; partial protection is not a safe deployed state. The concrete assertion should cover `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection.
- Expected Immunefi impact: High direct user or LP loss when later public actions rely on a half-initialized extension set.
- Fast validation: Create pools at and around fee boundaries and assert live swap fees plus fee-collection outputs match the configured protocol/admin split exactly.
