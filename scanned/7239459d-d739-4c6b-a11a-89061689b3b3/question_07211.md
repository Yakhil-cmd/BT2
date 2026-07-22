Q7211: binding mismatch in fee-collection path when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees` with extension arrays, extension orders, and `extensionInitData` lengths while the bin arrays populate only one side of the curve or leave one side empty, so that a field validated in one representation is bound in another, so the deployed pool trades against the wrong assumption along `collectPoolFees -> pool.collectFees -> fee split between protocol and admin destinations`, corrupting surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency? This is a public callable path, so even a non-admin can time fee collection against active state transitions if accounting is fragile. Craft a permissionless pool creation payload whose stored metadata and live behavior no longer agree on token, provider, or fee identity.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees -> metric-core/contracts/MetricOmmPool.sol::collectFees
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees
- Attacker controls: extension arrays, extension orders, and `extensionInitData` lengths
- Exploit idea: Reach `collectPoolFees -> pool.collectFees -> fee split between protocol and admin destinations` in a live public flow and show that craft a permissionless pool creation payload whose stored metadata and live behavior no longer agree on token, provider, or fee identity. The exact value at risk is surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency.
- Invariant to test: Every deployed pool must bind exactly the token pair, provider, fee schedule, and curve the factory accepted. The concrete assertion should cover surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency.
- Expected Immunefi impact: Critical direct loss if a public pool can be created with a mismatched provider or token binding that later misprices swaps or LP accounting.
- Fast validation: Trigger swaps and liquidity changes around public fee collection and assert every collected token matches accumulated fee state without touching LP principal.
