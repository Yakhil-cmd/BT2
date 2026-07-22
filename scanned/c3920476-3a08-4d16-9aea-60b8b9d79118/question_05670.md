Q5670: scale overflow or truncation in extension configuration gate when the provider is mutable and uses a finite timelock instead of the immutable mode

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while the provider is mutable and uses a finite timelock instead of the immutable mode, so that decimal-driven scaling is accepted at creation time but later breaks native/scaled conservation along `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance`, corrupting which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled? This gate decides whether a public pool creation request really wires every declared extension into the correct hook slots. Use a valid standard-token decimal combination and creation payload that pushes initial scaled state into a boundary the runtime math treats differently.

Target
- File/function: metric-core/contracts/libraries/ValidateExtensionsConfig.sol::validateExtensionsConfig
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance` in a live public flow and show that use a valid standard-token decimal combination and creation payload that pushes initial scaled state into a boundary the runtime math treats differently. The exact value at risk is which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Invariant to test: The factory must only deploy pools whose scale multipliers keep all later native/scaled conversions safe and exact within the documented rounding rules. The concrete assertion should cover which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Expected Immunefi impact: High direct loss or insolvency once live users swap or add liquidity to the malformed pool.
- Fast validation: Create pools with duplicate, sparse, and reordered extension orders and assert no reachable configuration can skip a required hook while still deploying successfully.
