Q4814: binding mismatch in scale-multiplier derivation when the bin arrays populate only one side of the curve or leave one side empty

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while the bin arrays populate only one side of the curve or leave one side empty, so that a field validated in one representation is bound in another, so the deployed pool trades against the wrong assumption along `createPool -> token metadata lookup -> scale multiplier derivation -> initial scaled amount computation`, corrupting token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants? A permissionless caller can choose any standard token pair, so decimal edge cases must be safe without an allowlist. Craft a permissionless pool creation payload whose stored metadata and live behavior no longer agree on token, provider, or fee identity.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_getScaleMultipliers
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> token metadata lookup -> scale multiplier derivation -> initial scaled amount computation` in a live public flow and show that craft a permissionless pool creation payload whose stored metadata and live behavior no longer agree on token, provider, or fee identity. The exact value at risk is token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants.
- Invariant to test: Every deployed pool must bind exactly the token pair, provider, fee schedule, and curve the factory accepted. The concrete assertion should cover token scale multipliers, initial scaled per-share amounts, and later native/scaled conversion invariants.
- Expected Immunefi impact: Critical direct loss if a public pool can be created with a mismatched provider or token binding that later misprices swaps or LP accounting.
- Fast validation: Deploy pools against mock standard ERC20s with varied decimals and assert every later add/swap/remove path preserves native-to-scaled consistency.
