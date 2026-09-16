### Title
Unbounded recursive `propagateFinalBad` cascade during MC stabilization can stall confirmation of new units - ([File: main_chain.js])

### Summary
`propagateFinalBad()` in `main_chain.js` recursively walks forward through the spending graph of every unit that becomes `final-bad`, marking each spender `final-bad` in turn and recursing again on the newly found spenders, with no depth/length cap analogous to the Solidity `while` loop in the Sherlock report that walked `ROUNDS_TO_BE_WOUNDED_BEFORE_DEAD` rounds killing every wounded agent without limit.

### Finding Description
When a main-chain index is stabilized, `markMcIndexStable()`'s `handleNonserialUnits()` determines which non-good units on that MCI are `final-bad` (double-spend losers), then calls: [1](#0-0) 
`propagateFinalBad(arrFinalBadUnits, addBalls)` is fully recursive: for every unit marked `final-bad`, it queries all units that spent an output of it (`SELECT ... FROM inputs ... WHERE src_unit IN(?)`), marks all of them `final-bad` too, and then calls itself again with that new list as the seed for the next hop: [2](#0-1) 
There is no maximum recursion depth, no cap on the number of units processed per stabilization, and no batching/`setImmediate` yielding as seen elsewhere in the same file (compare with `goDownAndCollectBestChildrenFast`, which explicitly yields every 100 iterations - `main_chain.js:1008-1014`). Each hop does two sequential `UPDATE` queries plus one `SELECT`, and the whole chain runs synchronously as part of `markMcIndexStable`, which itself runs under the write lock inside `saveJoint`/`advanceMcStability` (`writer.js:685-785`). An unprivileged unit poster who repeatedly double-spends the same output across a long chain of otherwise-valid units (A spends X's output, B spends A's output, C spends B's output, …) can build an arbitrarily long spend chain rooted in a losing double-spend. Once the root is resolved to `final-bad` at stabilization time, every descendant in that chain becomes a new seed for another recursive hop of `propagateFinalBad`, so the total work is proportional to the length of the attacker-controlled spend chain, with no upper bound enforced by the protocol (unlike `MAX_RESPONSES_PER_PRIMARY_TRIGGER` for AA chains, `main_chain.js`/`aa_composer.js:1846`, or `MAX_OPS` for oscript evaluation).

### Impact Explanation
This directly matches the report's impact class "network unable to confirm new units": stabilization (`markMcIndexStable`) runs under the `write` mutex while holding the DB transaction that also stabilizes the corresponding MCI for every node in the network. A sufficiently long crafted double-spend chain forces every full node to execute a correspondingly long, synchronous recursive `propagateFinalBad` cascade before that MCI (and therefore any following unit that depends on it becoming stable) can be marked stable, blocking write-lock progress for all subsequent joints and potentially causing the node to fall behind or become unresponsive during that period — a network-wide inability to move the stability point forward promptly.

### Likelihood Explanation
Building a long chain of units that all spend from one another is directly reachable by any unprivileged unit poster: post an output, then post a chain of units transferring/re-spending it, and finally post one alternate (double-spending) unit for the same original output so that the whole chain is retroactively resolved as `final-bad` once MC catches up. No special privileges, hub cooperation, or vulnerable peer state are required — it's a single actor constructing an ordinary-looking DAG of transfer units. The cost is only the standard commission/fees for posting that many units, which is the same low bar noted for the original report's "escapes can happen randomly and easily."

### Recommendation
Bound `propagateFinalBad`'s total work per stabilization step, e.g., cap the number of hops/total units processed (returning an error or deferring extra work to subsequent `setImmediate` ticks like `goDownAndCollectBestChildrenFast` does), or cap it via the existing spend-chain length constraints used elsewhere (similar to `MAX_RESPONSES_PER_PRIMARY_TRIGGER`). Alternatively, convert the recursive walk into an iterative batch process that periodically yields to the event loop so a single stabilization event cannot monopolize the write lock indefinitely regardless of chain length.

### Proof of Concept
1. Attacker posts unit `U0` with an output `O`.
2. Attacker posts a long serial chain `U1 → U2 → … → Un` each spending the previous unit's output (ordinary, valid-looking transfers), all authored by the attacker, of length `n` (as large as the attacker is willing to pay commissions for).
3. Attacker posts an alternate unit `U1'` that also spends `O` (a double-spend), positioned so that when the DAG stabilizes, `U1` (and thus the whole `U1..Un` chain) loses the double-spend race per the existing sequence/conflict rules in `findStableConflictingUnits`/`handleNonserialUnits` (`main_chain.js:1318-1365`).
4. When the relevant MCI stabilizes, `handleNonserialUnits` marks `U1` `final-bad` and calls `propagateFinalBad(['U1'], ...)`, which then recursively marks `U2`, `U3`, …, `Un` `final-bad` one hop at a time — `n` recursive rounds of `SELECT` + two `UPDATE` queries — all inside the single synchronous stabilization step holding the write lock, for every full node processing that MCI.

### Citations

**File:** main_chain.js (L1357-1360)
```javascript
						arrFinalBadUnits.forEach(function(unit){
							storage.assocStableUnits[unit].sequence = 'final-bad';
						});
						propagateFinalBad(arrFinalBadUnits, addBalls);
```

**File:** main_chain.js (L1383-1419)
```javascript
	function propagateFinalBad(arrFinalBadUnits, onPropagated){
		if (arrFinalBadUnits.length === 0)
			return onPropagated();
		conn.query("SELECT DISTINCT inputs.unit, main_chain_index FROM inputs LEFT JOIN units USING(unit) LEFT JOIN assets ON asset=assets.unit WHERE src_unit IN(?) AND (is_private=0 OR inputs.asset IS NULL)", [arrFinalBadUnits], function(rows){
			console.log("will propagate final-bad to", rows);
			if (rows.length === 0)
				return onPropagated();
			var arrSpendingUnits = rows.map(function(row){ return row.unit; });
			conn.query("UPDATE units SET sequence='final-bad' WHERE unit IN(?)", [arrSpendingUnits], function(){
			  // treat these units as non-existent competitors from now on
			  conn.query("UPDATE inputs SET is_unique=NULL WHERE unit IN(?)", [arrSpendingUnits], function(){
				var arrNewBadUnitsOnSameMci = [];
				rows.forEach(function (row) {
					var unit = row.unit;
					if (row.main_chain_index === mci) { // on the same MCI that we've just stabilized
						if (storage.assocStableUnits[unit].sequence !== 'final-bad') {
							storage.assocStableUnits[unit].sequence = 'final-bad';
							arrNewBadUnitsOnSameMci.push(unit);
						}
					}
					else { // on a future MCI
						storage.assocUnstableUnits[unit].sequence = 'final-bad';
						delete storage.assocUnstableMessages[unit];
					}
				});
				console.log("new final-bads on the same mci", arrNewBadUnitsOnSameMci);
				async.eachSeries(
					arrNewBadUnitsOnSameMci,
					setContentHash,
					function () {
						propagateFinalBad(arrSpendingUnits, onPropagated);
					}
				);
			  });
			});
		});
	}
```
