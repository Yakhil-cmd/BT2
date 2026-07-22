Q7730: hook-order hole in deployed fee configuration when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with mixed-decimal token pairs and initial per-share amounts near scaling boundaries while the bin arrays populate only one side of the curve or leave one side empty, so that an extension set looks enabled but a reachable order gap or duplicate causes a required hook not to run along `createPool -> protocol/admin fee aggregation -> pool constructor or factory-set fee state`, corrupting `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection? A permissionless pool creator can choose admin-side fees inside the documented bounds, so aggregation has to stay exact at deployment. Deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::createPool fee aggregation and metric-core/contracts/MetricOmmPool.sol::setPoolFees
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: mixed-decimal token pairs and initial per-share amounts near scaling boundaries
- Exploit idea: Reach `createPool -> protocol/admin fee aggregation -> pool constructor or factory-set fee state` in a live public flow and show that deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path. The exact value at risk is `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection.
- Invariant to test: Every configured hook must execute exactly as declared and in the validated order on live user flows. The concrete assertion should cover `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection.
- Expected Immunefi impact: High direct loss if an allowlist or oracle guard silently fails open on a production pool.
- Fast validation: Create pools at and around fee boundaries and assert live swap fees plus fee-collection outputs match the configured protocol/admin split exactly.
