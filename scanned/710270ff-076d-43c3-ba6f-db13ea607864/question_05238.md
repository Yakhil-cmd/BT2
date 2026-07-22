Q5238: binding mismatch in bin-data unpacking when both protocol and admin fees are non-zero from the first block of pool life

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while both protocol and admin fees are non-zero from the first block of pool life, so that a field validated in one representation is bound in another, so the deployed pool trades against the wrong assumption along `createPool -> packed bin arrays -> BinDataLibrary unpack -> initial BinState construction`, corrupting per-bin lengths, buy/sell add-on fees, lower/upper bin bounds, and the active curve geometry trusted by swaps? Public creators fully control the packed bin arrays, so every reachable unpacking edge case is a real deployment risk if validation is incomplete. Craft a permissionless pool creation payload whose stored metadata and live behavior no longer agree on token, provider, or fee identity.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_unpackAndValidateBinStates and metric-core/contracts/libraries/BinDataLibrary.sol
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> packed bin arrays -> BinDataLibrary unpack -> initial BinState construction` in a live public flow and show that craft a permissionless pool creation payload whose stored metadata and live behavior no longer agree on token, provider, or fee identity. The exact value at risk is per-bin lengths, buy/sell add-on fees, lower/upper bin bounds, and the active curve geometry trusted by swaps.
- Invariant to test: Every deployed pool must bind exactly the token pair, provider, fee schedule, and curve the factory accepted. The concrete assertion should cover per-bin lengths, buy/sell add-on fees, lower/upper bin bounds, and the active curve geometry trusted by swaps.
- Expected Immunefi impact: Critical direct loss if a public pool can be created with a mismatched provider or token binding that later misprices swaps or LP accounting.
- Fast validation: Fuzz packed bin arrays around fee and length boundaries and assert the resulting live pool curve matches the decoded configuration exactly.
