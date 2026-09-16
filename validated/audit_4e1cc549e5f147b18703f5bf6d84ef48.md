### Title
Stuck `is_spent=1` on outputs whose only spender became `final-bad` causes fund-freezing and balance under-counting - ([File: main_chain.js, writer.js, balances.js, network.js])

### Summary
This is the same bug class as the TokensFarmSDK issue: an accounting flag (`is_spent`) is set optimistically before the final "good/bad" status of the spending transaction is actually decided, and the flag is never reverted when the order of resolution reveals that the spend never really happened. In ocore this manifests as outputs whose only spending unit is later propagated to `sequence='final-bad'`: their `outputs.is_spent` flag stays `1` forever, even though no `good` unit actually consumes them.

### Finding Description
When a unit is written, `writer.js` marks every input's source output as spent immediately, before the unit's final sequence is known: [1](#0-0) 

Later, when the MCI stabilizes, `main_chain.js`'s `markMcIndexStable()` resolves conflicting claims and can also propagate `final-bad` status transitively to *non-conflicting* descendants of an already-final-bad unit via `propagateFinalBad()`: [2](#0-1) 

When a unit becomes `final-bad` this way, only `inputs.is_unique` is reset to `NULL`; the corresponding `outputs.is_spent` flag that was set at write time is never reverted to `0`: [3](#0-2) 

The only code path in the whole codebase that resets `outputs.is_spent` back to `0` is in `archiving.js`, and it runs solely when a joint is archived/voided (pruned units, "uncovered" reason) — not when a unit is simply demoted to `final-bad` while remaining in the DAG: [4](#0-3) 

The consequence is a "zombie-spent" output: a stable, `good` output that nobody can legitimately claim anymore (because its only claimant is `final-bad`), yet every balance/consensus query that filters on `is_spent=0` treats it as spent. This is explicitly documented as a real, previously-observed defect by the repository's own diagnostic tool and by a comment/fix inside `countVotes()`: [5](#0-4) [6](#0-5) 

Critically, that fix (`NOT EXISTS` query) was applied only to `countVotes()`. Every other balance-reading path in the codebase still relies on the naive `is_spent=0` filter and is therefore still vulnerable to the same under-counting/freezing:
- Wallet balance calculation: [7](#0-6) 
- Shared-address balance calculation: [8](#0-7) 
- Light client balances API (network-facing, callable by any peer): [9](#0-8) 
- System-vote balances API (network-facing): [10](#0-9) 

This exactly mirrors the reported bug class: an accounting field (`totalActiveStakeAmount` / `totalDeposits` in the report vs. `outputs.is_spent` here) is updated at the time of an action rather than when the action's finality is fully determined, and no code path reconciles it once a later, order-dependent finalization event (stake finalization order vs. `final-bad` propagation order) reveals the earlier assumption was wrong.

### Impact Explanation
An honest, unprivileged user can end up with an output that is permanently reported as spent although no valid unit actually spends it — the funds are frozen from the perspective of every balance-reporting code path except the (specifically patched) OP/system-vote counter. Since `balances.js` and `network.js`'s `light/get_balances` are what wallets use to determine spendable funds, users relying on this accounting can lose access to legitimate, stable, good byte outputs (fund loss/freezing), and light clients receive an incorrect, understated balance from full nodes via `light/get_balances` and `get_system_var_votes`.

### Likelihood Explanation
This requires that a unit spending some address's output is stabilized as `good` at first (or referenced), but later gets flipped to `final-bad` purely by `propagateFinalBad()` transitive propagation (i.e., an ancestor unrelated to this particular input becomes `final-bad`, e.g., due to a genuine double-spend conflict elsewhere authored by the same address, or an ancestor unit losing a serialization race). This is not an attacker-controlled network fault — it is a normal consequence of ocore's own nonserial/final-bad conflict-resolution algorithm reachable by any address that authors multiple units, one of which loses a double-spend race, causing all of its dependent (non-conflicting) descendant spends to be finalized as bad while the outputs they "spent" keep `is_spent=1`.

### Recommendation
When `propagateFinalBad()` (and the initial `sequence='final-bad'` assignment in `handleNonserialUnits`) demotes a unit, also reset `outputs.is_spent=0` for any output whose sole existing spender(s) are now all `final-bad` — mirroring exactly what `archiving.js`'s `generateQueriesToUnspendTransferOutputsSpentInArchivedUnit` already does for archived/voided joints. Additionally, replace every remaining naive `is_spent=0 ... sequence='good'` balance query (`balances.js`, `network.js`'s `light/get_balances` and `get_system_var_votes`) with the `NOT EXISTS`-based approach already adopted in `countVotes()`, so all balance-reporting paths are consistent and immune to zombie-spent outputs regardless of the order in which conflicting/descendant units are resolved to `final-bad`.

### Proof of Concept
1. Address `A` composes and broadcasts unit `U1` spending output `O` (a normal transfer). `U1` is initially unstable/good.
2. Address `A` (or a device desynchronized wallet copy) also broadcasts a genuinely conflicting unit `U2` that double-spends a *different* output belonging to `A`, in a way that causes `U2` to lose the double-spend race and become `final-bad` once its MCI stabilizes.
3. If `U1` happens to be a (possibly indirect) descendant of `U2` in the DAG's parent graph such that `U1` gets swept into `final-bad` by `propagateFinalBad()` triggered by `U2`'s demotion (main_chain.js:1383-1419), `U1` becomes `sequence='final-bad'`, yet `O.is_spent` was already set to `1` when `U1` was written (writer.js:380-382) and is never reset.
4. Query `balances.js`'s `readBalance()` (or call `light/get_balances`) for address `A`: output `O` is stable, `good`-sequence, and legitimately unspent (no `good` claimant exists for it), but it is excluded from the balance because `is_spent=1` — the funds appear frozen/lost to the owner, exactly reproducing the "zombie-spent outputs" scenario the repo's own `tools/compare_vote_balances.js` was written to detect for the vote-balance case.

### Citations

**File:** writer.js (L378-382)
```javascript
								switch (type){
									case "transfer":
										conn.addQuery(arrQueries, 
											"UPDATE outputs SET is_spent=1 WHERE unit=? AND message_index=? AND output_index=?",
											[src_unit, src_message_index, src_output_index]);
```

**File:** main_chain.js (L1337-1350)
```javascript
							conn.query("UPDATE units SET sequence=? WHERE unit=?", [sequence, row.unit], function(){
								if (sequence === 'good')
									conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], function(){
										storage.assocStableUnits[row.unit].sequence = 'good';
										cb();
									});
								else{
									arrFinalBadUnits.push(row.unit);
									// treat this unit as a non-existent competitor from now on
									conn.query("UPDATE inputs SET is_unique=NULL WHERE unit=?", [row.unit], function(){
										setContentHash(row.unit, cb);
									});
								}
							});
```

**File:** main_chain.js (L1382-1419)
```javascript
	// all future units that spent these unconfirmed units become final-bad too
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

**File:** main_chain.js (L1753-1773)
```javascript
	// Count all stable-good outputs that have no stable-good spender.
	// This correctly handles outputs whose only spending unit was propagated to final-bad
	// (leaving is_spent=1 in the DB while no good unit claims the output), which the
	// previous two-query approach (bal_rows + spent_rows) silently undercounted.
	const bal_rows = await conn.query(`
		SELECT outputs.address, SUM(outputs.amount) AS balance
		FROM outputs
		JOIN units ON outputs.unit = units.unit
		WHERE outputs.address IN(${strAddresses})
			AND outputs.asset IS NULL
			AND units.is_stable = 1 AND units.sequence = 'good'
			AND NOT EXISTS (
				SELECT 1 FROM inputs
				JOIN units AS su ON inputs.unit = su.unit
				WHERE inputs.src_unit = outputs.unit
					AND inputs.src_message_index = outputs.message_index
					AND inputs.src_output_index = outputs.output_index
					AND su.sequence = 'good'
					AND su.is_stable = 1
			)
		GROUP BY outputs.address`);
```

**File:** archiving.js (L121-147)
```javascript
function generateQueriesToUnspendTransferOutputsSpentInArchivedUnit(conn, unit, arrQueries, cb){
	conn.query(
		"SELECT src_unit, src_message_index, src_output_index \n\
		FROM inputs \n\
		WHERE inputs.unit=? \n\
			AND inputs.type='transfer' \n\
			AND NOT EXISTS ( \n\
				SELECT 1 FROM inputs AS alt_inputs \n\
				WHERE inputs.src_unit=alt_inputs.src_unit \n\
					AND inputs.src_message_index=alt_inputs.src_message_index \n\
					AND inputs.src_output_index=alt_inputs.src_output_index \n\
					AND alt_inputs.type='transfer' \n\
					AND inputs.unit!=alt_inputs.unit \n\
			)",
		[unit],
		function(rows){
			rows.forEach(function(row){
				conn.addQuery(
					arrQueries, 
					"UPDATE outputs SET is_spent=0 WHERE unit=? AND message_index=? AND output_index=?", 
					[row.src_unit, row.src_message_index, row.src_output_index]
				);
			});
			cb();
		}
	);
}
```

**File:** tools/compare_vote_balances.js (L1-9)
```javascript
/*jslint node: true */
'use strict';
// Compares voter balance calculations for system_vote subjects using two methods:
//   OLD: bal_rows (is_spent=0 stable-good) + spent_rows (unstable-good spending stable-good)
//   NEW: stable-good outputs with no stable-good spender (NOT EXISTS)
//
// A difference means the OLD method undercounts a voter's balance because a future
// unstable unit spent their stable output and was later propagated to final-bad,
// leaving is_spent=1 on the output while no good unit claims it in spent_rows.
```

**File:** balances.js (L14-18)
```javascript
	db.query(
		"SELECT asset, is_stable, SUM(CAST(amount AS DOUBLE)) AS balance \n\
		FROM outputs "+join_my_addresses+" CROSS JOIN units USING(unit) \n\
		WHERE is_spent=0 AND "+where_condition+" AND sequence='good' \n\
		GROUP BY asset, is_stable",
```

**File:** balances.js (L132-143)
```javascript
		db.query(
			"SELECT asset, address, is_stable, SUM(CAST(amount AS DOUBLE)) AS balance \n\
			FROM outputs CROSS JOIN units USING(unit) \n\
			WHERE is_spent=0 AND sequence='good' AND address IN("+strAddressList+") \n\
			GROUP BY asset, address, is_stable \n\
			UNION ALL \n\
			SELECT NULL AS asset, address, 1 AS is_stable, SUM(amount) AS balance FROM witnessing_outputs \n\
			WHERE is_spent=0 AND address IN("+strAddressList+") GROUP BY address \n\
			UNION ALL \n\
			SELECT NULL AS asset, address, 1 AS is_stable, SUM(amount) AS balance FROM headers_commission_outputs \n\
			WHERE is_spent=0 AND address IN("+strAddressList+") GROUP BY address",
			function(rows){
```

**File:** network.js (L3492-3496)
```javascript
					db.query(`SELECT address, SUM(amount) AS balance 
						FROM outputs
						LEFT JOIN units USING(unit)
						WHERE address IN(${strAddresses}) AND is_spent=0 AND asset IS NULL AND sequence='good' 
						GROUP BY address`,
```

**File:** network.js (L3885-3889)
```javascript
			db.query(
				"SELECT address, asset, is_stable, SUM(CAST(amount AS DOUBLE)) AS balance, COUNT(*) AS outputs_count \n\
				FROM outputs JOIN units USING(unit) \n\
				WHERE is_spent=0 AND address IN(?) AND sequence='good' \n\
				GROUP BY address, asset, is_stable", [addresses], function(rows) {
```
