Q7311: bin-topology confusion in fee-collection path when the provider is mutable and uses a finite timelock instead of the immutable mode

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees` with repeated public pool-creation attempts that reuse salts, tokens, or provider identities while the provider is mutable and uses a finite timelock instead of the immutable mode, so that packed bin data decodes into a live curve different from the one that validation or events implied along `collectPoolFees -> pool.collectFees -> fee split between protocol and admin destinations`, corrupting surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency? This is a public callable path, so even a non-admin can time fee collection against active state transitions if accounting is fragile. Build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees -> metric-core/contracts/MetricOmmPool.sol::collectFees
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees
- Attacker controls: repeated public pool-creation attempts that reuse salts, tokens, or provider identities
- Exploit idea: Reach `collectPoolFees -> pool.collectFees -> fee split between protocol and admin destinations` in a live public flow and show that build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended. The exact value at risk is surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency.
- Invariant to test: The live deployed bin topology must match the validated and emitted packed configuration exactly. The concrete assertion should cover surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency.
- Expected Immunefi impact: High bad-price execution or LP fund loss once the public pool goes live.
- Fast validation: Trigger swaps and liquidity changes around public fee collection and assert every collected token matches accumulated fee state without touching LP principal.
