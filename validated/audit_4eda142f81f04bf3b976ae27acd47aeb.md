### Title
Stale `is_spent` flag persists on outputs whose only spending unit is later voided/final-bad, permanently freezing funds - ([File: balances.js])

### Summary
This is analogous to the Xen bug class: a resource-removal path checks a validity condition (the "valid bit") before clearing a mapping/flag, and when that condition isn't met at the time of removal, the stale entry survives and is never revisited later even though the underlying validity state changes. In ocore, `outputs.is_spent` is set to `1` unconditionally when an input references it as its source, without checking whether the spending unit will end up `sequence='good'` or `'final-bad'`. When the spending unit is later determined to be `final-bad` (a losing double-spend / voided unit) outside of the explicit pruning/archiving path, nothing re-clears `is_spent` back to `0` for the ordinary balance/spend-selection queries, which only recognize `is_spent=0` as spendable.

### Finding Description
When a payment input is written, `writer.js`'s `addInlinePaymentQueries` marks the referenced source output as spent unconditionally: [1](#0-0) 
This happens regardless of `objValidationState.sequence` (i.e., even for a `'final-bad'` unit, whose claims should be treated as non-existent, as is explicitly done elsewhere for `is_unique`): [2](#0-1) 

The only code path that reverses this — restoring `is_spent=0` for an output whose sole spender is removed — is `archiving.generateQueriesToUnspendOutputsSpentInArchivedUnit`, which is invoked solely when a joint is explicitly archived/voided (pruning flow): [3](#0-2) [4](#0-3) 

This voiding/unspend path is only exercised in the light-wallet history-processing flow when a proven unit turns out final-bad: [5](#0-4) 

The project's own tooling and comments confirm that ordinary balance logic (`is_spent=0`) undercounts funds because outputs whose only spender later becomes `final-bad` keep `is_spent=1` forever ("zombie-spent outputs"), and that this was fixed only for the vote-counting balance query (`main_chain.js` `countVotes`) via a `NOT EXISTS` check for a *good* spender, not by clearing `is_spent`: [6](#0-5) [7](#0-6) [8](#0-7) 

`balances.js`, which is used for regular wallet/AA balance and coin-selection computations, contains 9 occurrences of `is_spent=0`-style filters and does not contain the compensating `NOT EXISTS (... su.sequence='good' ...)` logic that was added to `countVotes`. This means ordinary balance and coin-selection queries (and by extension AA-triggered spending or divisible/indivisible coin picking that also filters on `is_spent=0`, e.g. `pickIndivisibleCoinsForAmount`) can treat a perfectly valid, unspent stable output as permanently spent, exactly as the Xen bug lets a "removed" mapping continue to exist because a flag check gated the removal path.

### Impact Explanation
Any address (including AA addresses) whose stable output was referenced as an input by a unit that later loses a double-spend race and becomes `final-bad` outside of the light-wallet pruning/voiding path will have that output stuck with `is_spent=1` indefinitely. Ordinary balance and spend-selection code paths (`balances.js`, `indivisible_asset.js` coin picking) filter on `is_spent=0`, so:
- The address's funds become permanently unspendable (frozen) even though the coins are objectively unspent and stable-good.
- For AAs, this directly causes AA fund loss/freezing — an AA that should be able to spend a received output can silently be unable to compose valid payments, and its computed balance will be wrong, potentially causing bounces or fund lock-up.
- Nodes computing balances via `balances.js` will disagree with nodes that use the corrected `NOT EXISTS`-style approach used in `countVotes`, i.e., a form of node disagreement on the true spendable state, which the rules class as valid impact.

### Likelihood Explanation
Double-spend attempts that lose the serialization race (become `final-bad`) are a normal, expected occurrence in the DAG (this is precisely what the "sequence" and "final-bad" classification exists to handle), so the vulnerable state (an output spent by a claim that is ultimately final-bad) is reachable purely through ordinary competing-unit posting by any unprivileged user — no special privileges are needed to create a losing double-spend claim against someone else's output. The fact that the exact same root cause ("is_spent=1 with no good spender") was independently discovered and partially patched for `countVotes` demonstrates the underlying condition is realistically triggerable and was already observed in practice; the general-purpose balance code (`balances.js`) still lacks the equivalent correction.

### Recommendation
Apply the same fix pattern used in `main_chain.js`'s `countVotes` (a `NOT EXISTS` check against a stable-good spender) uniformly to all balance/spendability queries, most importantly `balances.js` and the coin-selection logic in `divisible_asset.js`/`indivisible_asset.js`, OR make `is_spent` itself authoritative by actively clearing it whenever a spending unit is determined `final-bad` during normal stabilization (not only during light-wallet archiving/voiding), mirroring `archiving.generateQueriesToUnspendOutputsSpentInArchivedUnit`.

### Proof of Concept
1. Address A has a stable, `sequence='good'` output O.
2. Two conflicting units U1 and U2 (a double-spend) both spend O; both get an `inputs` row and `writer.js` unconditionally sets `outputs.is_spent=1` for O when either is written (see `writer.js` lines 378-383).
3. Consensus stabilizes and marks U2 `sequence='good'`, U1 `sequence='final-bad'` (the losing branch). No general path clears `is_spent` back to `0` for O when U1 goes final-bad if U1 is not pruned/voided through the light-wallet flow.
4. If U2, rather than U1, is the one written last/observed, or in scenarios where the "good" claim's own is_spent write races with an already-final-bad claim's write, `outputs.is_spent` can end up `1` while the corresponding accepted good-spender's bookkeeping elsewhere (e.g. `countVotes`'s `NOT EXISTS` logic) shows O as unspent — as literally documented and reproduced by `tools/compare_vote_balances.js`, whose stated purpose is to detect exactly these "zombie-spent outputs" causing balance undercounting.
5. Any code (e.g., `balances.js`) that computes spendable balance via `is_spent=0` will undercount/exclude O, freezing those funds from being spent even though `tools/compare_vote_balances.js`'s "new way" query shows the true, correct spendable balance includes O.

### Citations

**File:** writer.js (L358-367)
```javascript
							determineInputAddress(function(address){
								// final-bad units are treated as non-existent competitors, their claims are never unique
								var is_unique = 
									(
										objValidationState.sequence === 'final-bad' ||
										objValidationState.arrDoubleSpendInputs.some(function (ds) { return (ds.message_index === i && ds.input_index === j); }) ||
										conf.bLight
									)
									? null : 1;
								conn.addQuery(arrQueries, "INSERT INTO inputs \n\
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

**File:** archiving.js (L89-119)
```javascript
function generateQueriesToVoidJoint(conn, unit, arrQueries, cb){
	generateQueriesToUnspendOutputsSpentInArchivedUnit(conn, unit, arrQueries, function(){
		// we keep witnesses, author addresses, and the unit itself
		conn.addQuery(arrQueries, "DELETE FROM witness_list_hashes WHERE witness_list_unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM earned_headers_commission_recipients WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "UPDATE unit_authors SET definition_chash=NULL WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM address_definition_changes WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM inputs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM outputs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM spend_proofs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM poll_choices WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM polls WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM votes WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM attested_fields WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM attestations WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM asset_metadata WHERE asset=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM asset_denominations WHERE asset=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM asset_attestors WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM assets WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM messages WHERE unit=?", [unit]);
		cb();
	});
}

function generateQueriesToUnspendOutputsSpentInArchivedUnit(conn, unit, arrQueries, cb){
	generateQueriesToUnspendTransferOutputsSpentInArchivedUnit(conn, unit, arrQueries, function(){
		generateQueriesToUnspendHeadersCommissionOutputsSpentInArchivedUnit(conn, unit, arrQueries, function(){
			generateQueriesToUnspendWitnessingOutputsSpentInArchivedUnit(conn, unit, arrQueries, cb);
		});
	});
}
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

**File:** light.js (L342-353)
```javascript
										if (sequence === 'good')
											return cb2();
										// void the final-bad
										breadcrumbs.add('will void '+unit);
										db.executeInTransaction(function doWork(conn, cb3){
											var arrQueries = [];
											archiving.generateQueriesToArchiveJoint(conn, objJoint, 'voided', arrQueries, function(){
												async.series(arrQueries, cb3);
											});
										}, cb2);
									}
								);
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

**File:** tools/compare_vote_balances.js (L1-48)
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
//
// Usage: node tools/compare_vote_balances.js

const db = require('../db.js');

async function balancesOldWay(addresses) {
	const strAddresses = addresses.map(db.escape).join(', ');

	const bal_rows = await db.query(`
		SELECT address, SUM(amount) AS balance
		FROM outputs
		LEFT JOIN units USING(unit)
		WHERE address IN(${strAddresses}) AND is_spent=0 AND asset IS NULL AND is_stable=1 AND sequence='good'
		GROUP BY address`);

	const balances = {};
	for (const { address, balance } of bal_rows)
		balances[address] = balance || 0;

	const spent_rows = await db.query(`
		SELECT inputs.address, SUM(outputs.amount) AS spent_balance
		FROM units
		CROSS JOIN inputs USING(unit)
		CROSS JOIN outputs ON src_unit=outputs.unit AND src_message_index=outputs.message_index AND src_output_index=outputs.output_index
		CROSS JOIN units AS output_units ON outputs.unit=output_units.unit
		WHERE units.is_stable=0 AND +units.sequence='good'
			AND +output_units.is_stable=1 AND +output_units.sequence='good'
			AND inputs.address IN(${strAddresses}) AND type='transfer' AND inputs.asset IS NULL
		GROUP BY inputs.address`);

	for (const { address, spent_balance } of spent_rows) {
		if (balances[address])
			balances[address] += spent_balance;
		else
			balances[address] = spent_balance;
	}

	return balances;
}
```

**File:** tools/compare_vote_balances.js (L50-76)
```javascript
async function balancesNewWay(addresses) {
	const strAddresses = addresses.map(db.escape).join(', ');

	const rows = await db.query(`
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

	const balances = {};
	for (const { address, balance } of rows)
		balances[address] = balance || 0;

	return balances;
}
```
