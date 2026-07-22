Q6947: hook-order hole in canonical registry identity when the provider is mutable and uses a finite timelock instead of the immutable mode

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with extension arrays, extension orders, and `extensionInitData` lengths while the provider is mutable and uses a finite timelock instead of the immutable mode, so that an extension set looks enabled but a reachable order gap or duplicate causes a required hook not to run along `createPool -> pool index assignment -> registry exposure to routers, quoters, and factory lookups`, corrupting the uniqueness of canonical pool identity used by routers, providers, and state-view consumers? A public caller can spam creation attempts and reuse salts; registry identity has to remain collision-free and canonical under that pressure. Deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::{idxToPool,poolToIdx,nextPoolIdx}
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: extension arrays, extension orders, and `extensionInitData` lengths
- Exploit idea: Reach `createPool -> pool index assignment -> registry exposure to routers, quoters, and factory lookups` in a live public flow and show that deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path. The exact value at risk is the uniqueness of canonical pool identity used by routers, providers, and state-view consumers.
- Invariant to test: Every configured hook must execute exactly as declared and in the validated order on live user flows. The concrete assertion should cover the uniqueness of canonical pool identity used by routers, providers, and state-view consumers.
- Expected Immunefi impact: High direct loss if an allowlist or oracle guard silently fails open on a production pool.
- Fast validation: Assert no repeated public creation pattern can make two pools share a registry slot or cause a canonical lookup to resolve the wrong address.
