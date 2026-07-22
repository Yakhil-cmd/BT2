Q4922: hook-order hole in scale-multiplier derivation when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with mixed-decimal token pairs and initial per-share amounts near scaling boundaries while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that an extension set looks enabled but a reachable order gap or duplicate causes a required hook not to run along `createPool -> token metadata lookup -> scale multiplier derivation -> initial scaled amount computation`, corrupting token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants? A permissionless caller can choose any standard token pair, so decimal edge cases must be safe without an allowlist. Deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_getScaleMultipliers
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: mixed-decimal token pairs and initial per-share amounts near scaling boundaries
- Exploit idea: Reach `createPool -> token metadata lookup -> scale multiplier derivation -> initial scaled amount computation` in a live public flow and show that deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path. The exact value at risk is token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants.
- Invariant to test: Every configured hook must execute exactly as declared and in the validated order on live user flows. The concrete assertion should cover token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants.
- Expected Immunefi impact: High direct loss if an allowlist or oracle guard silently fails open on a production pool.
- Fast validation: Deploy pools against mock standard ERC20s with varied decimals and assert every later add/swap/remove path preserves native-to-scaled consistency.
