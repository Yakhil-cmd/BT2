Q7822: identity collision in deployed fee configuration when the packed bin arrays sit near the documented 128-entry safety boundary

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while the packed bin arrays sit near the documented 128-entry safety boundary, so that public creation attempts can make canonical pool identity ambiguous for routers, providers, or state readers along `createPool -> protocol/admin fee aggregation -> pool constructor or factory-set fee state`, corrupting `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection? A permissionless pool creator can choose admin-side fees inside the documented bounds, so aggregation has to stay exact at deployment. Reuse salts, providers, or equivalent metadata to see whether the factory or deployer treats two distinct pools as the same canonical instance.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::createPool fee aggregation and metric-core/contracts/MetricOmmPool.sol::setPoolFees
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> protocol/admin fee aggregation -> pool constructor or factory-set fee state` in a live public flow and show that reuse salts, providers, or equivalent metadata to see whether the factory or deployer treats two distinct pools as the same canonical instance. The exact value at risk is `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection.
- Invariant to test: Every public pool creation must either revert or register a unique canonical identity consumed consistently across the stack. The concrete assertion should cover `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection.
- Expected Immunefi impact: High if integrations or price providers can be tricked into routing value to the wrong pool.
- Fast validation: Create pools at and around fee boundaries and assert live swap fees plus fee-collection outputs match the configured protocol/admin split exactly.
