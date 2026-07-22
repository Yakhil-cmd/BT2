Q4572: partial initialization in pool-parameter validation when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `adminSpreadFeeE6`, `adminNotionalFeeE8`, and `adminFeeDestination` values that appear within documented caps while the bin arrays populate only one side of the curve or leave one side empty, so that one extension is initialized with live pool state while another fails or binds to the wrong pool along `createPool -> _validatePoolParameters -> deploy-time state binding`, corrupting the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions? Any validation gap here lets a fully public caller mint a pool shape the rest of the system later trusts as safe. Use a public creation payload that leaves the pool only partially protected but still accepted by the factory and registry.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_validatePoolParameters
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `adminSpreadFeeE6`, `adminNotionalFeeE8`, and `adminFeeDestination` values that appear within documented caps
- Exploit idea: Reach `createPool -> _validatePoolParameters -> deploy-time state binding` in a live public flow and show that use a public creation payload that leaves the pool only partially protected but still accepted by the factory and registry. The exact value at risk is the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Invariant to test: Pool creation must be atomic across deploy plus extension initialization; partial protection is not a safe deployed state. The concrete assertion should cover the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Expected Immunefi impact: High direct user or LP loss when later public actions rely on a half-initialized extension set.
- Fast validation: Generate malformed but standard-ERC20 pool configs and assert every one that would later break swap/liquidity safety is rejected before deployment.
