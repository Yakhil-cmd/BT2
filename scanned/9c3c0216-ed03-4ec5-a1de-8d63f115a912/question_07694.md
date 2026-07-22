Q7694: bin-topology confusion in deployed fee configuration when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while the bin arrays populate only one side of the curve or leave one side empty, so that packed bin data decodes into a live curve different from the one that validation or events implied along `createPool -> protocol/admin fee aggregation -> pool constructor or factory-set fee state`, corrupting `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection? A permissionless pool creator can choose admin-side fees inside the documented bounds, so aggregation has to stay exact at deployment. Build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::createPool fee aggregation and metric-core/contracts/MetricOmmPool.sol::setPoolFees
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> protocol/admin fee aggregation -> pool constructor or factory-set fee state` in a live public flow and show that build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended. The exact value at risk is `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection.
- Invariant to test: The live deployed bin topology must match the validated and emitted packed configuration exactly. The concrete assertion should cover `spreadFeeE6`, `notionalFeeE8`, fee caps, and the live fee values later consumed by swaps and fee collection.
- Expected Immunefi impact: High bad-price execution or LP fund loss once the public pool goes live.
- Fast validation: Create pools at and around fee boundaries and assert live swap fees plus fee-collection outputs match the configured protocol/admin split exactly.
