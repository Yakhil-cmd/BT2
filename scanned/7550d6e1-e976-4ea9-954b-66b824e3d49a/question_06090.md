Q6090: bin-topology confusion in extension initialization calls when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with mixed-decimal token pairs and initial per-share amounts near scaling boundaries while the bin arrays populate only one side of the curve or leave one side empty, so that packed bin data decodes into a live curve different from the one that validation or events implied along `createPool -> deploy -> extension initialize loop -> per-extension state activation`, corrupting extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections? A public creator can choose many extension combinations, so partial-init or wrong-pool initialization must fail closed. Build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended.

Target
- File/function: metric-core/contracts/libraries/CallExtension.sol::callExtension and metric-periphery/contracts/extensions/base/BaseMetricExtension.sol::initialize
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: mixed-decimal token pairs and initial per-share amounts near scaling boundaries
- Exploit idea: Reach `createPool -> deploy -> extension initialize loop -> per-extension state activation` in a live public flow and show that build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended. The exact value at risk is extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Invariant to test: The live deployed bin topology must match the validated and emitted packed configuration exactly. The concrete assertion should cover extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Expected Immunefi impact: High bad-price execution or LP fund loss once the public pool goes live.
- Fast validation: Deploy pools with multiple extensions and assert every extension either initializes fully for that pool or causes the whole creation flow to revert.
