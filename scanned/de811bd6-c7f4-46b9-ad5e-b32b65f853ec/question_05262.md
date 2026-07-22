Q5262: scale overflow or truncation in bin-data unpacking when the packed bin arrays sit near the documented 128-entry safety boundary

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields while the packed bin arrays sit near the documented 128-entry safety boundary, so that decimal-driven scaling is accepted at creation time but later breaks native/scaled conservation along `createPool -> packed bin arrays -> BinDataLibrary unpack -> initial BinState construction`, corrupting per-bin lengths, buy/sell add-on fees, lower/upper bin bounds, and the active curve geometry trusted by swaps? Public creators fully control the packed bin arrays, so every reachable unpacking edge case is a real deployment risk if validation is incomplete. Use a valid standard-token decimal combination and creation payload that pushes initial scaled state into a boundary the runtime math treats differently.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_unpackAndValidateBinStates and metric-core/contracts/libraries/BinDataLibrary.sol
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: `nonNegativeBinDataArray` and `negativeBinDataArray` packed with edge-case lengths or fee fields
- Exploit idea: Reach `createPool -> packed bin arrays -> BinDataLibrary unpack -> initial BinState construction` in a live public flow and show that use a valid standard-token decimal combination and creation payload that pushes initial scaled state into a boundary the runtime math treats differently. The exact value at risk is per-bin lengths, buy/sell add-on fees, lower/upper bin bounds, and the active curve geometry trusted by swaps.
- Invariant to test: The factory must only deploy pools whose scale multipliers keep all later native/scaled conversions safe and exact within the documented rounding rules. The concrete assertion should cover per-bin lengths, buy/sell add-on fees, lower/upper bin bounds, and the active curve geometry trusted by swaps.
- Expected Immunefi impact: High direct loss or insolvency once live users swap or add liquidity to the malformed pool.
- Fast validation: Fuzz packed bin arrays around fee and length boundaries and assert the resulting live pool curve matches the decoded configuration exactly.
