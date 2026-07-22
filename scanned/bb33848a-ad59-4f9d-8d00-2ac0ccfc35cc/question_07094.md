Q7094: fee-cap drift in canonical registry identity when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while the bin arrays populate only one side of the curve or leave one side empty, so that publicly chosen admin-side fees remain within apparent bounds individually but aggregate unsafely when bound into live pool state along `createPool -> pool index assignment -> registry exposure to routers, quoters, and factory lookups`, corrupting the uniqueness of canonical pool identity used by routers, providers, and state-view consumers? A public caller can spam creation attempts and reuse salts; registry identity has to remain collision-free and canonical under that pressure. Pick a creation payload whose protocol-plus-admin fee aggregation lands on a runtime edge the swap path handles incorrectly.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::{idxToPool,poolToIdx,nextPoolIdx}
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> pool index assignment -> registry exposure to routers, quoters, and factory lookups` in a live public flow and show that pick a creation payload whose protocol-plus-admin fee aggregation lands on a runtime edge the swap path handles incorrectly. The exact value at risk is the uniqueness of canonical pool identity used by routers, providers, and state-view consumers.
- Invariant to test: Fee caps must hold after aggregation, not merely before, and live fee state must stay within the validated envelope. The concrete assertion should cover the uniqueness of canonical pool identity used by routers, providers, and state-view consumers.
- Expected Immunefi impact: Medium/High fee leakage or user overcharge above contest thresholds.
- Fast validation: Assert no repeated public creation pattern can make two pools share a registry slot or cause a canonical lookup to resolve the wrong address.
