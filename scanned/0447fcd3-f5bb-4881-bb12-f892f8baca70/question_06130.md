Q6130: hook-order hole in extension initialization calls when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with mixed-decimal token pairs and initial per-share amounts near scaling boundaries while the bin arrays populate only one side of the curve or leave one side empty, so that an extension set looks enabled but a reachable order gap or duplicate causes a required hook not to run along `createPool -> deploy -> extension initialize loop -> per-extension state activation`, corrupting extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections? A public creator can choose many extension combinations, so partial-init or wrong-pool initialization must fail closed. Deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path.

Target
- File/function: metric-core/contracts/libraries/CallExtension.sol::callExtension and metric-periphery/contracts/extensions/base/BaseMetricExtension.sol::initialize
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: mixed-decimal token pairs and initial per-share amounts near scaling boundaries
- Exploit idea: Reach `createPool -> deploy -> extension initialize loop -> per-extension state activation` in a live public flow and show that deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path. The exact value at risk is extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Invariant to test: Every configured hook must execute exactly as declared and in the validated order on live user flows. The concrete assertion should cover extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Expected Immunefi impact: High direct loss if an allowlist or oracle guard silently fails open on a production pool.
- Fast validation: Deploy pools with multiple extensions and assert every extension either initializes fully for that pool or causes the whole creation flow to revert.
