Q6215: identity collision in extension initialization calls when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with repeated public pool-creation attempts that reuse salts, tokens, or provider identities while the bin arrays populate only one side of the curve or leave one side empty, so that public creation attempts can make canonical pool identity ambiguous for routers, providers, or state readers along `createPool -> deploy -> extension initialize loop -> per-extension state activation`, corrupting extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections? A public creator can choose many extension combinations, so partial-init or wrong-pool initialization must fail closed. Reuse salts, providers, or equivalent metadata to see whether the factory or deployer treats two distinct pools as the same canonical instance.

Target
- File/function: metric-core/contracts/libraries/CallExtension.sol::callExtension and metric-periphery/contracts/extensions/base/BaseMetricExtension.sol::initialize
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: repeated public pool-creation attempts that reuse salts, tokens, or provider identities
- Exploit idea: Reach `createPool -> deploy -> extension initialize loop -> per-extension state activation` in a live public flow and show that reuse salts, providers, or equivalent metadata to see whether the factory or deployer treats two distinct pools as the same canonical instance. The exact value at risk is extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Invariant to test: Every public pool creation must either revert or register a unique canonical identity consumed consistently across the stack. The concrete assertion should cover extension-local storage, initialized flags, and whether one pool's configuration can partially activate another pool's protections.
- Expected Immunefi impact: High if integrations or price providers can be tricked into routing value to the wrong pool.
- Fast validation: Deploy pools with multiple extensions and assert every extension either initializes fully for that pool or causes the whole creation flow to revert.
