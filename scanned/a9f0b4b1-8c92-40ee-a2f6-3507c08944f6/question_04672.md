Q4672: mutable-provider mode confusion in pool-parameter validation when the provider is mutable and uses a finite timelock instead of the immutable mode

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with public `collectPoolFees` timing while a pool has fresh surplus or just crossed bins while the provider is mutable and uses a finite timelock instead of the immutable mode, so that the factory accepts a provider mode that runtime code interprets differently during later price-provider updates along `createPool -> _validatePoolParameters -> deploy-time state binding`, corrupting the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions? Any validation gap here lets a fully public caller mint a pool shape the rest of the system later trusts as safe. Choose creation parameters that make the pool think its provider is immutable while factory storage later treats it as mutable, or the reverse.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_validatePoolParameters
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: public `collectPoolFees` timing while a pool has fresh surplus or just crossed bins
- Exploit idea: Reach `createPool -> _validatePoolParameters -> deploy-time state binding` in a live public flow and show that choose creation parameters that make the pool think its provider is immutable while factory storage later treats it as mutable, or the reverse. The exact value at risk is the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Invariant to test: Provider mutability and update timelock semantics must be fixed and unambiguous from deployment onward. The concrete assertion should cover the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Expected Immunefi impact: Medium/High bad-price execution or admin-boundary break if the wrong provider can govern live swaps.
- Fast validation: Generate malformed but standard-ERC20 pool configs and assert every one that would later break swap/liquidity safety is rejected before deployment.
