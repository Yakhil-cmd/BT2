Q4484: bin-topology confusion in pool-parameter validation when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `adminSpreadFeeE6`, `adminNotionalFeeE8`, and `adminFeeDestination` values that appear within documented caps while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that packed bin data decodes into a live curve different from the one that validation or events implied along `createPool -> _validatePoolParameters -> deploy-time state binding`, corrupting the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions? Any validation gap here lets a fully public caller mint a pool shape the rest of the system later trusts as safe. Build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_validatePoolParameters
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `adminSpreadFeeE6`, `adminNotionalFeeE8`, and `adminFeeDestination` values that appear within documented caps
- Exploit idea: Reach `createPool -> _validatePoolParameters -> deploy-time state binding` in a live public flow and show that build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended. The exact value at risk is the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Invariant to test: The live deployed bin topology must match the validated and emitted packed configuration exactly. The concrete assertion should cover the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Expected Immunefi impact: High bad-price execution or LP fund loss once the public pool goes live.
- Fast validation: Generate malformed but standard-ERC20 pool configs and assert every one that would later break swap/liquidity safety is rejected before deployment.
