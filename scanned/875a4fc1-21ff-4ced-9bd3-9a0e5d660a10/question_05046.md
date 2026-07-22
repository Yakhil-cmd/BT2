Q5046: mutable-provider mode confusion in scale-multiplier derivation when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that the factory accepts a provider mode that runtime code interprets differently during later price-provider updates along `createPool -> token metadata lookup -> scale multiplier derivation -> initial scaled amount computation`, corrupting token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants? A permissionless caller can choose any standard token pair, so decimal edge cases must be safe without an allowlist. Choose creation parameters that make the pool think its provider is immutable while factory storage later treats it as mutable, or the reverse.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_getScaleMultipliers
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> token metadata lookup -> scale multiplier derivation -> initial scaled amount computation` in a live public flow and show that choose creation parameters that make the pool think its provider is immutable while factory storage later treats it as mutable, or the reverse. The exact value at risk is token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants.
- Invariant to test: Provider mutability and update timelock semantics must be fixed and unambiguous from deployment onward. The concrete assertion should cover token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants.
- Expected Immunefi impact: Medium/High bad-price execution or admin-boundary break if the wrong provider can govern live swaps.
- Fast validation: Deploy pools against mock standard ERC20s with varied decimals and assert every later add/swap/remove path preserves native-to-scaled consistency.
