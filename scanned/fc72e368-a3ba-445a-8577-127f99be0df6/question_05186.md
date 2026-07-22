Q5186: public fee-collection leakage in scale-multiplier derivation when the provider is mutable and uses a finite timelock instead of the immutable mode

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with mixed-decimal token pairs and initial per-share amounts near scaling boundaries while the provider is mutable and uses a finite timelock instead of the immutable mode, so that a public caller can time fee collection against a state transition that causes the pool to pay out more than accumulated fees along `createPool -> token metadata lookup -> scale multiplier derivation -> initial scaled amount computation`, corrupting token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants? A permissionless caller can choose any standard token pair, so decimal edge cases must be safe without an allowlist. Collect fees immediately after a live trade or liquidity transition and see whether surplus, protocol fees, and LP balances desynchronize.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_getScaleMultipliers
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: mixed-decimal token pairs and initial per-share amounts near scaling boundaries
- Exploit idea: Reach `createPool -> token metadata lookup -> scale multiplier derivation -> initial scaled amount computation` in a live public flow and show that collect fees immediately after a live trade or liquidity transition and see whether surplus, protocol fees, and lp balances desynchronize. The exact value at risk is token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants.
- Invariant to test: Public fee collection must extract only already-accrued fees and must never touch LP-owned principal. The concrete assertion should cover token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants.
- Expected Immunefi impact: High direct protocol or LP loss if public callers can trigger over-collection.
- Fast validation: Deploy pools against mock standard ERC20s with varied decimals and assert every later add/swap/remove path preserves native-to-scaled consistency.
