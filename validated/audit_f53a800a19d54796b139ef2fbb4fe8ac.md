### Title
Archiving/voiding a unit that already triggered an AA does not roll back its `aa_balances` credit, causing permanent phantom AA balances - (File: `ocore--016/archiving.js`, `ocore--016/aa_composer.js`)

### Summary
The reported ledger bug is a class of "derived-state cache diverges from the underlying data it was computed from once that data is pruned/archived." The Obyte AA-balance cache (`aa_balances`) is the exact analog of the ledger canister's balances table: it is incrementally updated from unit outputs (a form of "block" data), but the archiving/voiding code path that deletes outputs for units later found to be non-serial never adjusts `aa_balances` back down.

### Finding Description
When a unit pays into an AA address and is used as a trigger, `handleTrigger`'s `updateInitialAABalances` in `aa_composer.js` permanently credits the AA's cached balance directly in SQL: [1](#0-0) 
This update (and the equivalent bulk recompute in `storage.insertAADefinitions`, which also counts `is_stable=0 ... is_aa_response=1` outputs) can run against a unit that is still unstable ("unstable-good"), before the network has finished determining serial/non-serial order: [2](#0-1) 

Later, if that same triggering unit turns out to be non-serial (a double-spend loser) it is archived/voided. `joint_storage.purgeUncoveredNonserialJoints` finds `sequence IN('final-bad','temp-bad')` free units and calls `archiving.generateQueriesToArchiveJoint`, which dispatches to `generateQueriesToRemoveJoint`/`generateQueriesToVoidJoint`: [3](#0-2) [4](#0-3) 

These functions delete the unit's `outputs`, `inputs`, `messages`, and `aa_responses` rows and even unspend outputs that the archived unit itself had spent, but at no point do they issue a compensating `UPDATE aa_balances SET balance=balance-?` for any AA that had already been credited from this now-void unit's output. The `aa_balances` row was mutated directly and irreversibly the moment the trigger fired; the archiving code, which is generic ledger cleanup, has no knowledge of that AA-specific side effect and cannot reverse it.

This is precisely analogous to the reported bug: a derived balance table (`aa_balances` / ledger `balances`) is updated from source data (outputs / blocks) but is not kept consistent when that source data is later removed (archived) from the canonical record.

The existence of `aa_composer.checkBalances()` — a periodic consistency check comparing `aa_balances` against a live recomputation from `outputs` and throwing an error on mismatch — confirms the developers are aware such divergence is possible and have only a detect-and-crash safety net, not a preventive fix at the point of archiving: [5](#0-4) 

### Impact Explanation
If an AA is triggered by a unit that later loses a double-spend race and is archived, the AA keeps a permanently inflated balance for funds it never actually received (or the AA's response, already emitted using that balance, already spent/transferred real funds it had no legitimate right to). This is a concrete instance of AA fund loss / balance inflation reachable purely by an unprivileged AA trigger sender crafting conflicting units — no privileged access, malicious peer, or network-level attack is required. Depending on the AA logic, this phantom balance can be withdrawn, causing loss of funds to the AA (and, transitively, its legitimate users), or can desynchronize nodes that happen to run the `checkBalances` integrity check at different times relative to the archiving event, leading to a hard crash (`throw Error("checkBalances failed...")`), i.e., a node halting due to disagreement on validity of ledger state.

### Likelihood Explanation
Reaching this requires only: (1) crafting a payment to an AA address using coins that are simultaneously double-spent to another address, and (2) losing the double-spend race so the AA-triggering unit becomes non-serial and gets archived. Double-spending one's own inputs is trivially available to any unit author; no witness/hub/light-vendor collusion or elevated privileges are needed. The main uncertainty is precisely how much time elapses between an unstable-good AA response being finalized/propagated (funds spent) and the triggering unit later becoming `final-bad`/`temp-bad`, and whether that window is exploitable for withdrawal before it is caught by `checkBalances`; this needs deeper verification but the underlying data-integrity gap in `archiving.js` is unambiguous.

### Recommendation
When archiving or voiding a unit (`generateQueriesToRemoveJoint` / `generateQueriesToVoidJoint` in `archiving.js`), look up whether that unit ever contributed to an `aa_balances` credit (e.g., via `aa_responses`/trigger history) and issue a compensating decrement, or disallow non-final (unstable) units from ever crediting `aa_balances` until they are provably stable/serial, removing the "unstable-good" fast path for balance updates. Short term, extend `checkBalances` to run synchronously as part of the archiving transaction for any unit that has ever been an AA trigger, rather than as an out-of-band periodic job.

### Proof of Concept
1. Fund address `X` with a UTXO of amount `N`.
2. From `X`, post unit `A`: a payment output of `N` to AA address `AA1`. Because it is a valid unstable unit, it is queued in `aa_triggers` and processed via `handlePrimaryAATrigger` → `handleTrigger` → `updateInitialAABalances`, crediting `aa_balances[AA1].base += N` (`aa_composer.js:506-524`). Suppose the AA immediately forwards these funds out in its response.
3. Simultaneously (before `A` stabilizes), from `X` post a conflicting unit `B` spending the same output to address `Y`, arranged (via witness ordering / MC positioning) so that `B` wins and `A` becomes `sequence='final-bad'`/`temp-bad`.
4. `joint_storage.purgeUncoveredNonserialJoints` (or `storage.archiveJointAndDescendants`) archives/voids `A`, deleting its `outputs` row via `archiving.generateQueriesToRemoveJoint`/`generateQueriesToVoidJoint`, with no corresponding decrement of `aa_balances[AA1]`.
5. `AA1`'s `aa_balances` entry still reflects the `+N` credit and its response already forwarded `N` real bytes/asset units to a third party, even though the source output backing that credit no longer exists in the ledger — a net creation of `N` units of value at the AA's expense, only detectable later by the out-of-band `checkBalances()` job.

### Citations

**File:** aa_composer.js (L506-524)
```javascript
					conn.addQuery(
						arrQueries,
						"UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=? ",
						[trigger.outputs[row.asset], address, row.asset]
					);
					objValidationState.assocBalances[address][row.asset] = row.balance + trigger.outputs[row.asset];
					if (objValidationState.assocBalances[address][row.asset] > MAX_BALANCE)
						bOverflow = true;
				});
				// 2. insert balances of new assets
				var arrExistingAssets = rows.map(function (row) { return row.asset; });
				var arrNewAssets = _.difference(arrAssets, arrExistingAssets);
				if (arrNewAssets.length > 0) {
					var arrValues = arrNewAssets.map(function (asset) {
						objValidationState.assocBalances[address][asset] = trigger.outputs[asset];
						return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", " + trigger.outputs[asset] + ")"
					});
					conn.addQuery(arrQueries, "INSERT INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
				}
```

**File:** aa_composer.js (L1954-1990)
```javascript
function checkBalances() {
	mutex.lockOrSkip(['checkBalances'], function (unlock) {
		db.takeConnectionFromPool(function (conn) { // block conection for the entire duration of the check
			conn.query("SELECT 1 FROM aa_triggers", function (rows) {
				if (rows.length > 0) {
					console.log("skipping checkBalances because there are unhandled triggers");
					conn.release();
					return unlock();
				}
				var sql_create_temp = "CREATE TEMPORARY TABLE aa_outputs_balances ( \n\
					address CHAR(32) NOT NULL, \n\
					asset CHAR(44) NOT NULL, \n\
					calculated_balance BIGINT NOT NULL, \n\
					PRIMARY KEY (address, asset) \n\
				)" + (conf.storage === 'mysql' ? " ENGINE=MEMORY DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci" : "");
				var sql_fill_temp = "INSERT INTO aa_outputs_balances (address, asset, calculated_balance) \n\
					SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) \n\
					FROM aa_addresses \n\
					CROSS JOIN outputs USING(address) \n\
					CROSS JOIN units ON outputs.unit=units.unit \n\
					LEFT JOIN assets ON outputs.asset=assets.unit \n\
					WHERE is_spent=0 AND sequence='good' AND ( \n\
						is_stable=1 \n\
						OR is_stable=0 AND is_aa_response=1 \n\
					) AND (is_private=0 OR is_private IS NULL) \n\
					GROUP BY address, asset";
				var sql_balances_to_outputs = "SELECT aa_balances.address, aa_balances.asset, balance, calculated_balance \n\
				FROM aa_balances \n\
				LEFT JOIN aa_outputs_balances USING(address, asset) \n\
				GROUP BY aa_balances.address, aa_balances.asset \n\
				HAVING balance != IFNULL(calculated_balance, 0)";
				var sql_outputs_to_balances = "SELECT aa_outputs_balances.address, aa_outputs_balances.asset, balance, calculated_balance \n\
				FROM aa_outputs_balances \n\
				LEFT JOIN aa_balances USING(address, asset) \n\
				GROUP BY aa_outputs_balances.address, aa_outputs_balances.asset \n\
				HAVING IFNULL(balance, 0) != calculated_balance";
				var sql_drop_temp = db.dropTemporaryTable("aa_outputs_balances");
```

**File:** storage.js (L944-961)
```javascript
					var verb = bAlreadyPostedByUnconfirmedAA ? "REPLACE" : "INSERT";
					// pre-fix, the defining AA unit's own outputs are already in the outputs table and would be double-counted with its secondary trigger
					const or_sent_by_aa = (bAlreadyPostedByUnconfirmedAA || mci >= constants.pemCurvesFixMci) ? "OR is_aa_response=1" : "";
					// for AA-defined AAs, mci is the trigger mci whose triggers were already selected before this AA existed, so outputs on this mci can never trigger it and must be counted here.
					// Also count payments from other AA responses (never primary triggers) except the defining unit's own, which arrives as a secondary trigger
					const bImmediatelyVisible = bForAAsOnly && mci >= constants.pemCurvesFixMci;
					const mci_cond = bImmediatelyVisible
						? "(main_chain_index<=? OR is_aa_response=1) AND outputs.unit!=?"
						: "(main_chain_index<? " + or_sent_by_aa + ")"; // "<" for regular AAs, not including the outputs on the current mci, which will trigger the AA and be accounted for separately; is_aa_response=1 captures outputs to the not-yet-AA by AA responses
					const params = bImmediatelyVisible ? [address, mci, unit] : [address, mci];
					conn.query(
						verb + " INTO aa_balances (address, asset, balance) \n\
						SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) AS balance \n\
						FROM outputs \n\
						CROSS JOIN units USING(unit) \n\
						LEFT JOIN assets ON asset=assets.unit \n\
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
						GROUP BY address, asset",
```

**File:** joint_storage.js (L230-279)
```javascript
function purgeUncoveredNonserialJoints(bByExistenceOfChildren, onDone){
	var cond = bByExistenceOfChildren ? "(SELECT 1 FROM parenthoods WHERE parent_unit=unit LIMIT 1) IS NULL" : "is_free=1";
	var order_column = (conf.storage === 'mysql') ? 'creation_date' : 'rowid'; // this column must be indexed!
	var byIndex = (bByExistenceOfChildren && conf.storage === 'sqlite') ? 'INDEXED BY bySequence' : '';
	// the purged units can arrive again, no problem
	db.query( // purge the bad ball if we've already received at least 7 witnesses after receiving the bad ball
		"SELECT unit FROM units "+byIndex+" \n\
		WHERE "+cond+" AND sequence IN('final-bad','temp-bad') AND content_hash IS NULL \n\
			AND NOT EXISTS (SELECT * FROM dependencies WHERE depends_on_unit=units.unit) \n\
			AND NOT EXISTS (SELECT * FROM balls WHERE balls.unit=units.unit) \n\
			AND (units.creation_date < "+db.addTime('-10 SECOND')+" OR EXISTS ( \n\
				SELECT DISTINCT address FROM units AS wunits CROSS JOIN unit_authors USING(unit) CROSS JOIN my_witnesses USING(address) \n\
				WHERE wunits."+order_column+" > units."+order_column+" \n\
				LIMIT 0,1 \n\
			)) \n\
			/* AND NOT EXISTS (SELECT * FROM unhandled_joints) */ \n\
		ORDER BY units."+order_column+" DESC", 
		// some unhandled joints may depend on the unit to be archived but it is not in dependencies because it was known when its child was received
	//	[constants.MAJORITY_OF_WITNESSES - 1],
		function(rows){
			if (rows.length === 0)
				return onDone();
			mutex.lock(["write"], function(unlock) {
				db.takeConnectionFromPool(function (conn) {
					async.eachSeries(
						rows,
						function (row, cb) {
							breadcrumbs.add("--------------- archiving uncovered unit " + row.unit);
							storage.readJoint(conn, row.unit, {
								ifNotFound: function () {
									throw Error("nonserial unit not found?");
								},
								ifFound: function (objJoint) {
									var arrQueries = [];
									conn.addQuery(arrQueries, "BEGIN");
									archiving.generateQueriesToArchiveJoint(conn, objJoint, 'uncovered', arrQueries, function(){
										conn.addQuery(arrQueries, "COMMIT");
										// sql goes first, deletion from kv is the last step
										async.series(arrQueries, function(){
											kvstore.del('j\n'+row.unit, function(){
												breadcrumbs.add("------- done archiving "+row.unit);
												var parent_units = storage.assocUnstableUnits[row.unit].parent_units;
												storage.forgetUnit(row.unit);
												storage.fixIsFreeAfterForgettingUnit(parent_units);
												cb();
											});
										});
									});
								}
							});
```

**File:** archiving.js (L49-111)
```javascript
function generateQueriesToArchiveJoint(conn, objJoint, reason, arrQueries, cb){
	var func = (reason === 'uncovered') ? generateQueriesToRemoveJoint : generateQueriesToVoidJoint;
	func(conn, objJoint.unit.unit, arrQueries, function(){
		conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO archived_joints (unit, reason, json) VALUES (?,?,?)", 
			[objJoint.unit.unit, reason, JSON.stringify(objJoint)]);
		cb();
	});
}

function generateQueriesToRemoveJoint(conn, unit, arrQueries, cb){
	generateQueriesToUnspendOutputsSpentInArchivedUnit(conn, unit, arrQueries, function(){
		conn.addQuery(arrQueries, "DELETE FROM aa_responses WHERE trigger_unit=? OR response_unit=?", [unit, unit]);
		conn.addQuery(arrQueries, "DELETE FROM original_addresses WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM sent_mnemonics WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM witness_list_hashes WHERE witness_list_unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM earned_headers_commission_recipients WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM unit_witnesses WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM unit_authors WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM parenthoods WHERE child_unit=?", [unit]);
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
	//	conn.addQuery(arrQueries, "DELETE FROM balls WHERE unit=?", [unit]); // if it has a ball, it can't be uncovered
		conn.addQuery(arrQueries, "DELETE FROM units WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM joints WHERE unit=?", [unit]);
		cb();
	});
}

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
```
