Q4688: fee-cap drift in pool-parameter validation when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with public `collectPoolFees` timing while a pool has fresh surplus or just crossed bins while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that publicly chosen admin-side fees remain within apparent bounds individually but aggregate unsafely when bound into live pool state along `createPool -> _validatePoolParameters -> deploy-time state binding`, corrupting the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions? Any validation gap here lets a fully public caller mint a pool shape the rest of the system later trusts as safe. Pick a creation payload whose protocol-plus-admin fee aggregation lands on a runtime edge the swap path handles incorrectly.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_validatePoolParameters
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: public `collectPoolFees` timing while a pool has fresh surplus or just crossed bins
- Exploit idea: Reach `createPool -> _validatePoolParameters -> deploy-time state binding` in a live public flow and show that pick a creation payload whose protocol-plus-admin fee aggregation lands on a runtime edge the swap path handles incorrectly. The exact value at risk is the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Invariant to test: Fee caps must hold after aggregation, not merely before, and live fee state must stay within the validated envelope. The concrete assertion should cover the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Expected Immunefi impact: Medium/High fee leakage or user overcharge above contest thresholds.
- Fast validation: Generate malformed but standard-ERC20 pool configs and assert every one that would later break swap/liquidity safety is rejected before deployment.
