Q7271: scale overflow or truncation in fee-collection path when the provider is mutable and uses a finite timelock instead of the immutable mode

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees` with repeated public pool-creation attempts that reuse salts, tokens, or provider identities while the provider is mutable and uses a finite timelock instead of the immutable mode, so that decimal-driven scaling is accepted at creation time but later breaks native/scaled conservation along `collectPoolFees -> pool.collectFees -> fee split between protocol and admin destinations`, corrupting surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency? This is a public callable path, so even a non-admin can time fee collection against active state transitions if accounting is fragile. Use a valid standard-token decimal combination and creation payload that pushes initial scaled state into a boundary the runtime math treats differently.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees -> metric-core/contracts/MetricOmmPool.sol::collectFees
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::collectPoolFees
- Attacker controls: repeated public pool-creation attempts that reuse salts, tokens, or provider identities
- Exploit idea: Reach `collectPoolFees -> pool.collectFees -> fee split between protocol and admin destinations` in a live public flow and show that use a valid standard-token decimal combination and creation payload that pushes initial scaled state into a boundary the runtime math treats differently. The exact value at risk is surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency.
- Invariant to test: The factory must only deploy pools whose scale multipliers keep all later native/scaled conversions safe and exact within the documented rounding rules. The concrete assertion should cover surplus balances, protocol-fee destination amounts, admin-fee destination amounts, and remaining pool solvency.
- Expected Immunefi impact: High direct loss or insolvency once live users swap or add liquidity to the malformed pool.
- Fast validation: Trigger swaps and liquidity changes around public fee collection and assert every collected token matches accumulated fee state without touching LP principal.
