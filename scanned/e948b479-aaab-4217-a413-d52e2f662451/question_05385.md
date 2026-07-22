Q5385: partial initialization in bin-data unpacking when the provider is mutable and uses a finite timelock instead of the immutable mode

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with permissionless `createPool` calldata for token ordering, salt, and initial bin arrays while the provider is mutable and uses a finite timelock instead of the immutable mode, so that one extension is initialized with live pool state while another fails or binds to the wrong pool along `createPool -> packed bin arrays -> BinDataLibrary unpack -> initial BinState construction`, corrupting per-bin lengths, buy/sell add-on fees, lower/upper bin bounds, and the active curve geometry trusted by swaps? Public creators fully control the packed bin arrays, so every reachable unpacking edge case is a real deployment risk if validation is incomplete. Use a public creation payload that leaves the pool only partially protected but still accepted by the factory and registry.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_unpackAndValidateBinStates and metric-core/contracts/libraries/BinDataLibrary.sol
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: permissionless `createPool` calldata for token ordering, salt, and initial bin arrays
- Exploit idea: Reach `createPool -> packed bin arrays -> BinDataLibrary unpack -> initial BinState construction` in a live public flow and show that use a public creation payload that leaves the pool only partially protected but still accepted by the factory and registry. The exact value at risk is per-bin lengths, buy/sell add-on fees, lower/upper bin bounds, and the active curve geometry trusted by swaps.
- Invariant to test: Pool creation must be atomic across deploy plus extension initialization; partial protection is not a safe deployed state. The concrete assertion should cover per-bin lengths, buy/sell add-on fees, lower/upper bin bounds, and the active curve geometry trusted by swaps.
- Expected Immunefi impact: High direct user or LP loss when later public actions rely on a half-initialized extension set.
- Fast validation: Fuzz packed bin arrays around fee and length boundaries and assert the resulting live pool curve matches the decoded configuration exactly.
