Q6172: partial initialization in extension initialization calls when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `adminSpreadFeeE6`, `adminNotionalFeeE8`, and `adminFeeDestination` values that appear within documented caps while the bin arrays populate only one side of the curve or leave one side empty, so that one extension is initialized with live pool state while another fails or binds to the wrong pool along `createPool -> deploy -> extension initialize loop -> per-extension state activation`, corrupting extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections? A public creator can choose many extension combinations, so partial-init or wrong-pool initialization must fail closed. Use a public creation payload that leaves the pool only partially protected but still accepted by the factory and registry.

Target
- File/function: metric-core/contracts/libraries/CallExtension.sol::callExtension and metric-periphery/contracts/extensions/base/BaseMetricExtension.sol::initialize
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `adminSpreadFeeE6`, `adminNotionalFeeE8`, and `adminFeeDestination` values that appear within documented caps
- Exploit idea: Reach `createPool -> deploy -> extension initialize loop -> per-extension state activation` in a live public flow and show that use a public creation payload that leaves the pool only partially protected but still accepted by the factory and registry. The exact value at risk is extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Invariant to test: Pool creation must be atomic across deploy plus extension initialization; partial protection is not a safe deployed state. The concrete assertion should cover extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Expected Immunefi impact: High direct user or LP loss when later public actions rely on a half-initialized extension set.
- Fast validation: Deploy pools with multiple extensions and assert every extension either initializes fully for that pool or causes the whole creation flow to revert.
