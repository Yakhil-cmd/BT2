Q7041: mutable-provider mode confusion in canonical registry identity when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with permissionless `createPool` calldata for token ordering, salt, and initial bin arrays while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that the factory accepts a provider mode that runtime code interprets differently during later price-provider updates along `createPool -> pool index assignment -> registry exposure to routers, quoters, and factory lookups`, corrupting the uniqueness of canonical pool identity used by routers, providers, and state-view consumers? A public caller can spam creation attempts and reuse salts; registry identity has to remain collision-free and canonical under that pressure. Choose creation parameters that make the pool think its provider is immutable while factory storage later treats it as mutable, or the reverse.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::{idxToPool,poolToIdx,nextPoolIdx}
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: permissionless `createPool` calldata for token ordering, salt, and initial bin arrays
- Exploit idea: Reach `createPool -> pool index assignment -> registry exposure to routers, quoters, and factory lookups` in a live public flow and show that choose creation parameters that make the pool think its provider is immutable while factory storage later treats it as mutable, or the reverse. The exact value at risk is the uniqueness of canonical pool identity used by routers, providers, and state-view consumers.
- Invariant to test: Provider mutability and update timelock semantics must be fixed and unambiguous from deployment onward. The concrete assertion should cover the uniqueness of canonical pool identity used by routers, providers, and state-view consumers.
- Expected Immunefi impact: Medium/High bad-price execution or admin-boundary break if the wrong provider can govern live swaps.
- Fast validation: Assert no repeated public creation pattern can make two pools share a registry slot or cause a canonical lookup to resolve the wrong address.
