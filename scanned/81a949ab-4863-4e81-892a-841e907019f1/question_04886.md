Q4886: bin-topology confusion in scale-multiplier derivation when the pool uses a 6/18 token pair with non-zero initial liquidity per share

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while the pool uses a 6/18 token pair with non-zero initial liquidity per share, so that packed bin data decodes into a live curve different from the one that validation or events implied along `createPool -> token metadata lookup -> scale multiplier derivation -> initial scaled amount computation`, corrupting token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants? A permissionless caller can choose any standard token pair, so decimal edge cases must be safe without an allowlist. Build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_getScaleMultipliers
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> token metadata lookup -> scale multiplier derivation -> initial scaled amount computation` in a live public flow and show that build a public create-pool payload where length or fee packing makes runtime swaps traverse a different curve than intended. The exact value at risk is token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants.
- Invariant to test: The live deployed bin topology must match the validated and emitted packed configuration exactly. The concrete assertion should cover token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants.
- Expected Immunefi impact: High bad-price execution or LP fund loss once the public pool goes live.
- Fast validation: Deploy pools against mock standard ERC20s with varied decimals and assert every later add/swap/remove path preserves native-to-scaled consistency.
