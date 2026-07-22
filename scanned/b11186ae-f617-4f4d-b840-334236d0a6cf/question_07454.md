Q7454: mutable-provider mode confusion in fee-collection path when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while the bin arrays populate only one side of the curve or leave one side empty, so that the factory accepts a provider mode that runtime code interprets differently during later price-provider updates along `collectPoolFees -> pool.collectFees -> fee split between protocol and admin destinations`, corrupting surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency? This is a public callable path, so even a non-admin can time fee collection against active state transitions if accounting is fragile. Choose creation parameters that make the pool think its provider is immutable while factory storage later treats it as mutable, or the reverse.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees -> metric-core/contracts/MetricOmmPool.sol::collectFees
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `collectPoolFees -> pool.collectFees -> fee split between protocol and admin destinations` in a live public flow and show that choose creation parameters that make the pool think its provider is immutable while factory storage later treats it as mutable, or the reverse. The exact value at risk is surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency.
- Invariant to test: Provider mutability and update timelock semantics must be fixed and unambiguous from deployment onward. The concrete assertion should cover surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency.
- Expected Immunefi impact: Medium/High bad-price execution or admin-boundary break if the wrong provider can govern live swaps.
- Fast validation: Trigger swaps and liquidity changes around public fee collection and assert every collected token matches accumulated fee state without touching LP principal.
