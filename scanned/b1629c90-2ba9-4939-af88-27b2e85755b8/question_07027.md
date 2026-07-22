Q7027: identity collision in canonical registry identity when the provider is mutable and uses a finite timelock instead of the immutable mode

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with extension arrays, extension orders, and `extensionInitData` lengths while the provider is mutable and uses a finite timelock instead of the immutable mode, so that public creation attempts can make canonical pool identity ambiguous for routers, providers, or state readers along `createPool -> pool index assignment -> registry exposure to routers, quoters, and factory lookups`, corrupting the uniqueness of canonical pool identity used by routers, providers, and state-view consumers? A public caller can spam creation attempts and reuse salts; registry identity has to remain collision-free and canonical under that pressure. Reuse salts, providers, or equivalent metadata to see whether the factory or deployer treats two distinct pools as the same canonical instance.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::{idxToPool,poolToIdx,nextPoolIdx}
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: extension arrays, extension orders, and `extensionInitData` lengths
- Exploit idea: Reach `createPool -> pool index assignment -> registry exposure to routers, quoters, and factory lookups` in a live public flow and show that reuse salts, providers, or equivalent metadata to see whether the factory or deployer treats two distinct pools as the same canonical instance. The exact value at risk is the uniqueness of canonical pool identity used by routers, providers, and state-view consumers.
- Invariant to test: Every public pool creation must either revert or register a unique canonical identity consumed consistently across the stack. The concrete assertion should cover the uniqueness of canonical pool identity used by routers, providers, and state-view consumers.
- Expected Immunefi impact: High if integrations or price providers can be tricked into routing value to the wrong pool.
- Fast validation: Assert no repeated public creation pattern can make two pools share a registry slot or cause a canonical lookup to resolve the wrong address.
