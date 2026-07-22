Q6065: scale overflow or truncation in extension initialization calls when the provider is mutable and uses a finite timelock instead of the immutable mode

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with permissionless `createPool` calldata for token ordering, salt, and initial bin arrays while the provider is mutable and uses a finite timelock instead of the immutable mode, so that decimal-driven scaling is accepted at creation time but later breaks native/scaled conservation along `createPool -> deploy -> extension initialize loop -> per-extension state activation`, corrupting extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections? A public creator can choose many extension combinations, so partial-init or wrong-pool initialization must fail closed. Use a valid standard-token decimal combination and creation payload that pushes initial scaled state into a boundary the runtime math treats differently.

Target
- File/function: metric-core/contracts/libraries/CallExtension.sol::callExtension and metric-periphery/contracts/extensions/base/BaseMetricExtension.sol::initialize
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: permissionless `createPool` calldata for token ordering, salt, and initial bin arrays
- Exploit idea: Reach `createPool -> deploy -> extension initialize loop -> per-extension state activation` in a live public flow and show that use a valid standard-token decimal combination and creation payload that pushes initial scaled state into a boundary the runtime math treats differently. The exact value at risk is extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Invariant to test: The factory must only deploy pools whose scale multipliers keep all later native/scaled conversions safe and exact within the documented rounding rules. The concrete assertion should cover extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Expected Immunefi impact: High direct loss or insolvency once live users swap or add liquidity to the malformed pool.
- Fast validation: Deploy pools with multiple extensions and assert every extension either initializes fully for that pool or causes the whole creation flow to revert.
