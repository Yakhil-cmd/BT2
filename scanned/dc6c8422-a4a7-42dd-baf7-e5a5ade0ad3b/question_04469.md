Q4469: scale overflow or truncation in pool-parameter validation when the provider is mutable and uses a finite timelock instead of the immutable mode

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `priceProvider`, `priceProviderTimelock`, and immutable-vs-mutable provider mode selection while the provider is mutable and uses a finite timelock instead of the immutable mode, so that decimal-driven scaling is accepted at creation time but later breaks native/scaled conservation along `createPool -> _validatePoolParameters -> deploy-time state binding`, corrupting the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions? Any validation gap here lets a fully public caller mint a pool shape the rest of the system later trusts as safe. Use a valid standard-token decimal combination and creation payload that pushes initial scaled state into a boundary the runtime math treats differently.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_validatePoolParameters
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `priceProvider`, `priceProviderTimelock`, and immutable-vs-mutable provider mode selection
- Exploit idea: Reach `createPool -> _validatePoolParameters -> deploy-time state binding` in a live public flow and show that use a valid standard-token decimal combination and creation payload that pushes initial scaled state into a boundary the runtime math treats differently. The exact value at risk is the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Invariant to test: The factory must only deploy pools whose scale multipliers keep all later native/scaled conversions safe and exact within the documented rounding rules. The concrete assertion should cover the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Expected Immunefi impact: High direct loss or insolvency once live users swap or add liquidity to the malformed pool.
- Fast validation: Generate malformed but standard-ERC20 pool configs and assert every one that would later break swap/liquidity safety is rejected before deployment.
