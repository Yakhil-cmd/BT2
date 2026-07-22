Q6248: mutable-provider mode confusion in extension initialization calls when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with public `collectPoolFees` timing while a pool has fresh surplus or just crossed bins while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that the factory accepts a provider mode that runtime code interprets differently during later price-provider updates along `createPool -> deploy -> extension initialize loop -> per-extension state activation`, corrupting extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections? A public creator can choose many extension combinations, so partial-init or wrong-pool initialization must fail closed. Choose creation parameters that make the pool think its provider is immutable while factory storage later treats it as mutable, or the reverse.

Target
- File/function: metric-core/contracts/libraries/CallExtension.sol::callExtension and metric-periphery/contracts/extensions/base/BaseMetricExtension.sol::initialize
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: public `collectPoolFees` timing while a pool has fresh surplus or just crossed bins
- Exploit idea: Reach `createPool -> deploy -> extension initialize loop -> per-extension state activation` in a live public flow and show that choose creation parameters that make the pool think its provider is immutable while factory storage later treats it as mutable, or the reverse. The exact value at risk is extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Invariant to test: Provider mutability and update timelock semantics must be fixed and unambiguous from deployment onward. The concrete assertion should cover extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Expected Immunefi impact: Medium/High bad-price execution or admin-boundary break if the wrong provider can govern live swaps.
- Fast validation: Deploy pools with multiple extensions and assert every extension either initializes fully for that pool or causes the whole creation flow to revert.
