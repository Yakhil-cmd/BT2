### Title
Zombie is_spent flag leaves stable outputs permanently unspendable / balance-undercounted when spending unit is voted final-bad - (File: main_chain.js)

### Summary
This is analogous to the reported class of bug: a piece of "usage state" attached to an entity (there, `allocation`; here, the output's `is_spent` flag) is not reset when the entity that caused it becomes invalid/deactivated. In `ocore`, when a competing spender of a stable output loses the parent-consistency race and is marked `final-bad` in `main_chain.js`'s `markMcIndexStable()`/`handleNonserialUnits()`, the flag `outputs.is_spent=1` that was set on the source output when the (now-invalid) spending unit was originally written is never cleared, unless the invalid unit is later fully archived/voided via `archiving.js`. As long as the `final-bad` unit stays in the `units` table (which is the normal, long-term state for `final-bad` units that are not "uncovered" and pruned), the legitimately owned, stable, good-sequence output remains falsely marked as spent.

### Finding Description
When a unit is written by `writer.saveJoint()` and consumes a `transfer` input, the source output is immediately updated: `UPDATE outputs SET is_spent=1 WHERE unit=? AND message_index=? AND output_index=?` (`writer.js:379-383`). This happens optimistically, before the consuming unit's ultimate sequence (`good` vs `final-bad`) is finally settled at the DAG level in cases of double-spends/forked paths.

Later, during stabilization, `main_chain.js:markMcIndexStable()` -> `handleNonserialUnits()` determines the final sequence of competing units at a given MCI:
```
main_chain.js:1334-1349
findStableConflictingUnits(row, function(arrConflictingUnits){
    var sequence = (arrConflictingUnits.length > 0) ? 'final-bad' : 'good';
    conn.query("UPDATE units SET sequence=? WHERE unit=?", [sequence, row.unit], function(){
        if (sequence === 'good')
            conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], ...);
        else{
            ...
            conn.query("UPDATE inputs SET is_unique=NULL WHERE unit=?", [row.unit], ...);
        }
    });
});
``` [1](#0-0) 

Notice: when a unit becomes `final-bad`, only `inputs.is_unique` is cleared on the *loser's own* inputs table row — the `outputs.is_spent` flag on the *source output it spent* is never reset back to `0`. The only code path that clears `is_spent` back to `0` for such outputs is in `archiving.js`'s `generateQueriesToUnspendTransferOutputsSpentInArchivedUnit()`, which only runs when the bad unit is fully archived/voided (`generateQueriesToRemoveJoint`/`generateQueriesToVoidJoint`), a separate, later, and not-always-triggered process (`joint_storage.purgeUncoveredNonserialJoints`, or light-client `void` on `light.js:344-351`). [2](#0-1) 

This is the same root-cause pattern as the Rio LRT report: a stateful side-effect (`allocation` there, `is_spent` here) that was set as a consequence of an entity's original (later-invalidated) status is not rolled back when that entity's status changes (deactivated cap / final-bad sequence), leaving a stale value that desynchronizes the "real" state (true unspent balance) from the tracked state (`is_spent=1`), exactly mirroring the acknowledged "zombie-spent output" issue already documented in `tools/compare_vote_balances.js`:
```
tools/compare_vote_balances.js:1-9
// A difference means the OLD method undercounts a voter's balance because a future
// unstable unit spent their stable output and was later propagated to final-bad,
// leaving is_spent=1 on the output while no good unit claims it in spent_rows.
``` [3](#0-2) 

The vote-balance calculation in `main_chain.js:countVotes()` was fixed to use a `NOT EXISTS` join against `sequence='good' AND is_stable=1` inputs rather than trusting the `is_spent` flag directly: [4](#0-3) 

However, numerous other consensus/wallet-facing balance and coin-selection queries throughout the codebase still trust the raw `is_spent=0` flag without this compensating `NOT EXISTS` check, e.g.:
- `balances.js:readOutputsBalance/readSharedBalance/readAllUnspentOutputs` (wallet balance and total supply reporting) [5](#0-4) 
- `inputs.js:pickDivisibleCoinsForAmount` (composer coin-selection for real payments) [6](#0-5) 
- `aa_composer.js:readStableOutputs` (AA's own coin-selection when it needs to construct payment outputs) [7](#0-6) 
- `network.js` `get_system_var_votes` balance query [8](#0-7) 

### Impact Explanation
Because a losing/`final-bad` spender's claim leaves `is_spent=1` on the honest owner's stable output indefinitely (until the bad unit is separately archived), that output silently disappears from:
1. Wallet/composer coin selection (`inputs.js`, `indivisible_asset.js`) — the address's own funds become unspendable ("stuck"/frozen funds) even though the address never actually lost them.
2. Balance reporting APIs (`balances.js`, `network.js` votes endpoint) — under-reporting a genuine, good, stable balance.
3. AA response construction (`aa_composer.js:readStableOutputs`) — an AA may be unable to satisfy outgoing payments it should be able to afford, causing it to bounce triggers or under-fund responses.

This matches the "AA fund loss or freezing" / inability to spend legitimately available funds impact bucket called for by the rules, driven purely by a routine double-spend/fork resolution outcome that any node naturally experiences — no malicious peer/hub/node cooperation is required beyond the normal existence of a losing conflicting unit on the DAG (e.g., an address author simply issuing two conflicting payments from forked parents, a completely permitted and common scenario). The freezing is silent and permanent for that output unless/until the archiving/pruning machinery separately clears it.

### Likelihood Explanation
Double-spends/forked-parent conflicts that get resolved with one branch becoming `final-bad` are a normal, expected part of DAG consensus (not attacker-exclusive); any unprivileged unit poster can trigger this by posting two units that spend the same output along different, ultimately-conflicting parent paths. Because `final-bad` units are commonly retained rather than immediately pruned (pruning/"uncovered" archiving only removes them under specific conditions after enough confirmations, see `joint_storage.purgeUncoveredNonserialJoints`), the stale `is_spent=1` state on the honest output can persist for extended periods in ordinary operation, making the discrepancy realistically reachable, as evidenced by the project's own diagnostic tool (`tools/compare_vote_balances.js`) built specifically to detect these "zombie-spent outputs" in production databases.

### Recommendation
Apply the same fix pattern already used for `countVotes()` uniformly wherever `is_spent=0` is relied upon to determine spendable/available balance:
- Either (a) actively reset `outputs.is_spent=0` for the source output as soon as its spending unit is finalized as `final-bad` in `handleNonserialUnits()` (mirroring what `archiving.generateQueriesToUnspendTransferOutputsSpentInArchivedUnit` already does, but triggered immediately at stabilization time rather than only at archival time), or
- (b) replace direct `is_spent=0` filters in balance/coin-selection queries (`balances.js`, `inputs.js`, `indivisible_asset.js`, `aa_composer.js`, `network.js`) with the `NOT EXISTS (... sequence='good' AND is_stable=1 ...)` pattern already adopted in `main_chain.js:countVotes()`.

### Proof of Concept
1. Address A owns a stable, good, unspent output O (e.g. 1,000,000 bytes).
2. A composes two conflicting units, U1 and U2, each spending O to different recipients, built on different (incompatible) parent sets, and gets both broadcast/accepted as unhandled/unstable joints (`writer.saveJoint` sets `outputs.is_spent=1` on O for whichever is processed first, e.g. U1).
3. As the MC advances and MCI stabilizes, `main_chain.js:findStableConflictingUnits` determines U1 loses (becomes `final-bad`) while U2 (or neither) becomes `good`. In `handleNonserialUnits`, U1's `sequence` is set to `'final-bad'` and its `inputs.is_unique` cleared, but no query resets `outputs.is_spent` for output O.
4. If U2's inclusion actually spends a different output, or if U2 never gets included/stabilized, O now permanently shows `is_spent=1` in the DB despite having no good, stable spender.
5. Any subsequent call to `balances.js:readOutputsBalance(A)`, `inputs.js:pickDivisibleCoinsForAmount` (composing a real payment from A), or an AA at address A trying to spend O via `aa_composer.js:readStableOutputs`, silently excludes O from A's available balance — A's (or the AA's) legitimate funds become inaccessible until/unless U1 is separately archived and O's `is_spent` is reset by `archiving.js`.

### Citations

**File:** main_chain.js (L1334-1349)
```javascript
						findStableConflictingUnits(row, function(arrConflictingUnits){
							var sequence = (arrConflictingUnits.length > 0) ? 'final-bad' : 'good';
							console.log("unit "+row.unit+" has competitors "+arrConflictingUnits+", it becomes "+sequence);
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
```

**File:** main_chain.js (L1753-1774)
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
	console.log('bal rows', bal_rows)
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

**File:** balances.js (L76-94)
```javascript
	db.query(
		"SELECT asset, is_stable, SUM(CAST(amount AS DOUBLE)) AS balance \n\
		FROM outputs "+join_my_addresses+" CROSS JOIN units USING(unit) \n\
		WHERE is_spent=0 AND "+where_condition+" AND sequence='good' \n\
		GROUP BY asset, is_stable",
		[wallet],
		function(rows){
			for (var i=0; i<rows.length; i++){
				var row = rows[i];
				var asset = row.asset || "base";
				if (!assocBalances[asset])
					assocBalances[asset] = {stable: 0, pending: 0};
				assocBalances[asset][row.is_stable ? 'stable' : 'pending'] = row.balance;
			}
			for (var asset in assocBalances)
				assocBalances[asset].total = assocBalances[asset].stable + assocBalances[asset].pending;
			handleBalance(assocBalances);
		}
	);
```

**File:** inputs.js (L99-126)
```javascript
		conn.query(
			`SELECT unit, message_index, output_index, amount, blinding, address
			FROM outputs
			CROSS JOIN units USING(unit)
			${conf.bLight ? "LEFT JOIN aa_responses ON unit=response_unit" : ""}
			WHERE address IN(?) AND asset${asset ? "="+conn.escape(asset) : " IS NULL"} AND is_spent=0 AND amount ${more} ?
				AND sequence='good' ${confirmation_condition}
				${constants.bDevnet
					? ""
					: (conf.bLight
						? `AND ( response_unit IS NULL OR aa_responses.creation_date<${conn.addTime('-30 SECOND')} )`
						: `AND ( units.is_aa_response IS NULL OR units.creation_date<${conn.addTime('-30 SECOND')} )`
					)
				}
			ORDER BY is_stable DESC, amount LIMIT 1`,
			[arrSpendableAddresses, net_required_amount + transfer_input_size + getOversizeFee(size + transfer_input_size)],
			function(rows){
				if (rows.length === 1){
					var input = rows[0];
					// default type is "transfer"
					addInput(input);
					onDone(arrInputsWithProofs, total_amount);
				}
				else
					pickMultipleCoinsAndContinue();
			}
		);
	}
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

**File:** network.js (L3492-3496)
```javascript
					db.query(`SELECT address, SUM(amount) AS balance 
						FROM outputs
						LEFT JOIN units USING(unit)
						WHERE address IN(${strAddresses}) AND is_spent=0 AND asset IS NULL AND sequence='good' 
						GROUP BY address`,
```
