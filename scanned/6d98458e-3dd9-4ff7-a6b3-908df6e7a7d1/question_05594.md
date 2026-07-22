Q5594: public fee-collection leakage in bin-data unpacking when both protocol and admin fees are non-zero from the first block of pool life

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with mixed-decimal token pairs and initial per-share amounts near scaling boundaries while both protocol and admin fees are non-zero from the first block of pool life, so that a public caller can time fee collection against a state transition that causes the pool to pay out more than accumulated fees along `createPool -> packed bin arrays -> BinDataLibrary unpack -> initial BinState construction`, corrupting per-bin lengths, buy/sell add-on fees, lower/upper bin bounds, and the active curve geometry trusted by swaps? Public creators fully control the packed bin arrays, so every reachable unpacking edge case is a real deployment risk if validation is incomplete. Collect fees immediately after a live trade or liquidity transition and see whether surplus, protocol fees, and LP balances desynchronize.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_unpackAndValidateBinStates and metric-core/contracts/libraries/BinDataLibrary.sol
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: mixed-decimal token pairs and initial per-share amounts near scaling boundaries
- Exploit idea: Reach `createPool -> packed bin arrays -> BinDataLibrary unpack -> initial BinState construction` in a live public flow and show that collect fees immediately after a live trade or liquidity transition and see whether surplus, protocol fees, and lp balances desynchronize. The exact value at risk is per-bin lengths, buy/sell add-on fees, lower/upper bin bounds, and the active curve geometry trusted by swaps.
- Invariant to test: Public fee collection must extract only already-accrued fees and must never touch LP-owned principal. The concrete assertion should cover per-bin lengths, buy/sell add-on fees, lower/upper bin bounds, and the active curve geometry trusted by swaps.
- Expected Immunefi impact: High direct protocol or LP loss if public callers can trigger over-collection.
- Fast validation: Fuzz packed bin arrays around fee and length boundaries and assert the resulting live pool curve matches the decoded configuration exactly.
