Q5731: hook-order hole in extension configuration gate when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with extension arrays, extension orders, and `extensionInitData` lengths while the bin arrays populate only one side of the curve or leave one side empty, so that an extension set looks enabled but a reachable order gap or duplicate causes a required hook not to run along `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance`, corrupting which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled? This gate decides whether a public pool creation request really wires every declared extension into the correct hook slots. Deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path.

Target
- File/function: metric-core/contracts/libraries/ValidateExtensionsConfig.sol::validateExtensionsConfig
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: extension arrays, extension orders, and `extensionInitData` lengths
- Exploit idea: Reach `createPool -> ValidateExtensionsConfig.validateExtensionsConfig -> extension order acceptance` in a live public flow and show that deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path. The exact value at risk is which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Invariant to test: Every configured hook must execute exactly as declared and in the validated order on live user flows. The concrete assertion should cover which hooks are actually enforced, in what order, and whether a pool silently launches without a protection the creator thought was enabled.
- Expected Immunefi impact: High direct loss if an allowlist or oracle guard silently fails open on a production pool.
- Fast validation: Create pools with duplicate, sparse, and reordered extension orders and assert no reachable configuration can skip a required hook while still deploying successfully.
