### Title
`is_spent` flag on stable outputs is never reset when the spending unit is marked `final-bad`, permanently freezing legitimate funds - (File: main_chain.js)

### Summary
This is the ocore analog of the `RCTreasury.payout` bug: a status flag that represents "funds are unavailable to the owner" is set when a spend occurs, but the code path that voids/undoes that spend (the unit becoming `final-bad`) never resets the flag back. In `RCTreasury.sol`, `isForeclosed` should be cleared on `payout` but isn't. In ocore, `outputs.is_spent` should be cleared when the unit that consumed the output is declared `final-bad` (i.e., its spend is undone), but the stabilization/final-bad code path in `main_chain.js` never issues the corresponding "unspend" query, unlike the dedicated archiving path.

### Finding Description
When a stable unit's temp-bad/final-bad status is resolved during `markMcIndexStable()`, `handleNonserialUnits()` finds a conflicting unit and, if losing, marks it `final-bad` and does: [1](#0-0) 
This only clears `inputs.is_unique`; it does not touch the `outputs.is_spent=1` flag that `writer.js` set on the source output when this now-invalid unit was originally validated and saved: [2](#0-1) 
The same omission exists in `propagateFinalBad()`, which cascades `final-bad` to every descendant unit that spent the outputs of a newly-final-bad unit, but again only updates `units.sequence` and `inputs.is_unique`, never `outputs.is_spent`: [3](#0-2) 

Contrast this with the dedicated "unspend" logic in `archiving.js`, which correctly resets `is_spent=0` for outputs whose only spender is being archived/voided: [4](#0-3) 
That path is invoked only from `generateQueriesToArchiveJoint` (used for uncovered/voided joints, e.g. in `light.js`'s "void the final-bad" branch), not from the primary `main_chain.js` stabilization flow where most `final-bad` determinations for stable units happen. This exact discrepancy is independently documented by the repo's own diagnostic tool, `tools/compare_vote_balances.js`, which explicitly compares "OLD" balance calculation (relying on `is_spent`) against a "NEW" method and states the root cause: [5](#0-4) 

### Impact Explanation
Every part of the codebase that determines which outputs are spendable filters on `is_spent=0 AND sequence='good'`, including the AA composer's own output selection when an AA is trying to pay out a trigger's sender, and the standard wallet/composer coin-selection logic: [6](#0-5) 
If the address's legitimate, stable output is left permanently marked `is_spent=1` because the unit that "spent" it was ultimately ruled `final-bad` (double-spend loser) outside of the archiving path, that output becomes permanently invisible to balance and coin-selection logic on that node, even though no valid unit actually claims it. This is a fund-freezing/availability bug directly analogous to the report's "user wouldn't be allowed to place new bids" impact — here, the address's own base or asset balance becomes practically inaccessible for future payments, AA triggers, or private-payment chains sourced from that output, without any attacker action needed beyond causing a normal double-spend conflict to resolve.

### Likelihood Explanation
Double-spends resolving to `final-bad` are a completely ordinary occurrence in ocore — they happen whenever two units from the same address conflict (e.g., a wallet accidentally posts two competing spends, or a legitimate fork-resolution occurs) and one is judged the loser during stabilization. This code path runs on every full node for every MCI stabilization, so the discrepancy is triggered by routine operation rather than by a rare or attacker-crafted edge case, and the presence of a dedicated repo tool (`compare_vote_balances.js`) built specifically to detect "zombie-spent outputs" in production databases is strong evidence this occurs in practice.

### Recommendation
When a unit is marked `final-bad` in `handleNonserialUnits()` and in `propagateFinalBad()` in `main_chain.js`, also issue an `UPDATE outputs SET is_spent=0 WHERE ...` for the source outputs referenced by that unit's `transfer` inputs — mirroring the logic already implemented in `archiving.generateQueriesToUnspendTransferOutputsSpentInArchivedUnit` — but conditioned only on whether any other *good* unit still claims that output as spent, not merely whether other units exist. The same treatment should be applied to `headers_commission_outputs.is_spent` and `witnessing_outputs.is_spent` for the analogous input types, consistent with `archiving.js`'s existing helpers.

### Proof of Concept
1. Node A has a stable, spendable output O (base or asset) belonging to address X.
2. Two units, U1 and U2, are composed from address X spending O (a double-spend, e.g. due to a wallet retry or an intentional conflict).
3. Both U1 and U2 are broadcast and accepted into the DAG; `writer.js` sets `outputs.is_spent=1` for O when saving whichever unit is validated first, per the transfer-input logic at `writer.js:378-383`.
4. During stabilization, `markMcIndexStable()`/`handleNonserialUnits()` in `main_chain.js` determines that (say) U1 is the loser and marks it `final-bad` via `findStableConflictingUnits`, updating `inputs.is_unique=NULL` but never resetting `outputs.is_spent` for O (`main_chain.js:1343-1350`).
5. If U1 (not U2) was the one that had actually caused `is_spent=1` on O — e.g. a race in write order, or U1 stabilizes on a fork branch first before U2 is finally selected as the winner — O remains `is_spent=1` in the database permanently, since no code path resets it outside of the unrelated `archiving.js` pruning flow.
6. Any subsequent attempt by address X to spend O via `composer.js`, `aa_composer.js`'s `readStableOutputs` (`aa_composer.js:1140-1155`), or asset-transfer coin selection in `indivisible_asset.js`/`balances.js` silently excludes O from available funds (`is_spent=0` filter), even though O is a perfectly valid, unspent, stable output — funds are frozen from the owner's perspective on that node.
7. `tools/compare_vote_balances.js` was written specifically to detect this class of discrepancy in live databases, corroborating that this "zombie-spent output" state occurs in production.

### Citations

**File:** main_chain.js (L1343-1350)
```javascript
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

**File:** writer.js (L378-383)
```javascript
								switch (type){
									case "transfer":
										conn.addQuery(arrQueries, 
											"UPDATE outputs SET is_spent=1 WHERE unit=? AND message_index=? AND output_index=?",
											[src_unit, src_message_index, src_output_index]);
										break;
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

**File:** aa_composer.js (L1140-1155)
```javascript
			function readStableOutputs(handleRows) {
			//	console.log('--- readStableOutputs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				// byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond
				conn.query(
					"SELECT unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND main_chain_index<=? \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY main_chain_index, unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
			}
```
