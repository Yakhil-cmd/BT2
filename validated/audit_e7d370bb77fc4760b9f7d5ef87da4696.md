This confirms the analog: `count_aa_responses` is read fresh from the SQL `units` table on startup (`initStableUnits`/`readUnitProps` in `storage.js`), and `aa_triggers` rows are only removed via the `DELETE FROM aa_triggers` statement inside the same MySQL transaction as the `count_aa_responses` update [1](#0-0) . The kvstore (LevelDB) batch containing all state-variable writes and the response unit's joint is flushed to disk with `batch.write({sync:true}, ...)` *before* the SQL `COMMIT` is issued [2](#0-1) .

### Title
Non-atomic ordering between kvstore batch write and SQL commit in AA trigger processing enables duplicate execution of the same primary trigger - (File: aa_composer.js)

### Summary
`handlePrimaryAATrigger` durably persists all effects of an AA trigger (state variables, response unit, balances) to the LevelDB key-value store via `batch.write({sync:true})` *before* committing the corresponding SQL transaction that deletes the `aa_triggers` row and increments `units.count_aa_responses` [3](#0-2) . If the process crashes or the connection is lost between the successful kvstore write and the SQL `COMMIT`, the SQL transaction is rolled back on restart, but the kvstore effects remain permanently applied.

### Finding Description
The processing pipeline is:
1. `handleTrigger` computes state updates, balances, and a response unit, and populates a `batch` object with all writes (state vars, response joint) [4](#0-3) .
2. Inside the still-open SQL transaction, `DELETE FROM aa_triggers ...` and `UPDATE units SET count_aa_responses=...` are executed, and the in-memory cache `storage.assocStableUnits[unit].count_aa_responses` is bumped [5](#0-4) .
3. Only after that, `batch.write({sync:true}, ...)` durably persists the kvstore batch to LevelDB.
4. Only after the kvstore batch succeeds does the code call `conn.query("COMMIT", ...)` to finalize the SQL transaction [2](#0-1) .

Because the kvstore write happens and is confirmed *before* the SQL commit, a crash (process kill, OOM, DB connection failure) occurring after the LevelDB `sync:true` write returns but before the MySQL `COMMIT` completes leaves the system in an inconsistent state:
- LevelDB: state vars already updated, response unit's joint already saved.
- SQL (rolled back automatically on an incomplete/aborted connection): `aa_triggers` row for `(mci, unit, address)` still present, and `units.count_aa_responses` for the trigger unit still at its old (unincremented) value.

On restart, in-memory caches are rebuilt strictly from the SQL tables (`initStableUnits`/`readUnitProps` read `count_aa_responses` from `units`, and `handleAATriggers` re-selects all rows still present in `aa_triggers`) [6](#0-5) [7](#0-6) . Since the `aa_triggers` row was never actually deleted (the delete was part of the rolled-back transaction) and `count_aa_responses` reverted to its pre-execution value, `handleAATriggers` will re-select and reprocess the same primary trigger. The re-entrancy guard that is supposed to prevent double execution of the same trigger unit — `storage.assocStableUnits[trigger.unit].count_aa_responses` check at the top of AA evaluation — reads a value of `0`/unset because it was never durably committed, so the guard silently passes and the AA logic executes a second time on top of the already-mutated state vars from the first (uncommitted-in-SQL but committed-in-kvstore) run [8](#0-7) .

This is directly analogous to the referenced Tigris `GovNFT` bug: an operation's durable "effect" (minting the NFT / here, applying AA state changes and producing a response unit) is applied without the corresponding "consumed" marker (deleting `failedMessages` / here, the SQL `aa_triggers` deletion and `count_aa_responses` increment) being committed atomically with it. A partial failure between the two steps allows the same logical operation to be replayed and applied twice.

### Impact Explanation
Re-execution of the same primary AA trigger produces a second, distinct AA response unit (new state var mutations layered on top of already-mutated ones, second set of payment outputs) written to the DAG. Depending on the AA's logic this can duplicate token issuance/transfers, double-credit balances, double-execute financial logic (e.g., double payout, double state counter increments), effectively causing fund loss or duplication for the AA and its counterparties — an AA fund-loss/inflation scenario consistent with the accepted-impact class for this analog scan (AA fund loss or supply inflation via duplicated state effects).

### Likelihood Explanation
This requires the node process to crash or lose its database connection during the specific narrow window between the LevelDB `sync:true` batch write completing and the MySQL `COMMIT` finishing — an external/operational condition rather than something an attacker directly triggers, similar to the original report which also relies on an external failure condition (endpoint retrying). Because it depends on an uncontrolled crash timing window, likelihood is not attacker-controlled but is realistic for any long-running node (crashes, OOM kills, DB failover) and is the same class of judged-Medium severity as the original finding (external condition triggered issue in FSM ordering).

### Recommendation
Reorder the persistence so that the "consumption" marker is committed atomically with (or before) the irreversible kvstore effects, or make the kvstore write idempotent/replayable against a durably-recorded processed marker. Concretely:
- Commit the SQL transaction (which deletes `aa_triggers` and updates `count_aa_responses`) *before* or atomically with the kvstore `batch.write`, or
- Persist a durable "trigger already applied" marker in the kvstore batch itself (in the same atomic LevelDB batch as the state var/response writes) that `handleAATriggers` checks before reprocessing a trigger, so a crash between the two stores cannot cause replay of the trigger's effects without also being recognized as already consumed.

### Proof of Concept
1. An AA trigger unit becomes stable and is picked up by `handleAATriggers` → `handlePrimaryAATrigger`.
2. `handleTrigger` runs, producing state var updates and a response unit, added to the `batch`.
3. `DELETE FROM aa_triggers ...` and `UPDATE units SET count_aa_responses=...` execute inside the open SQL transaction (not yet committed).
4. `batch.write({sync:true}, cb)` succeeds — state vars and the response joint are now durably in LevelDB.
5. Process crashes (e.g., killed, OOM, or the MySQL connection drops) before `conn.query("COMMIT", ...)` executes/finishes.
6. On restart, the SQL transaction is rolled back: the `aa_triggers` row for this trigger still exists, and `units.count_aa_responses` for the trigger unit is back to its pre-run value; `storage.assocStableUnits` is rebuilt from this stale, uncommitted-free DB state.
7. `handleAATriggers` re-selects the pending `aa_triggers` row and calls `handlePrimaryAATrigger` again for the same `(mci, unit, address)`.
8. The re-entrancy guard `storage.assocStableUnits[trigger.unit].count_aa_responses` reads `0`, so it does not block re-execution.
9. `handleTrigger` runs a second time, reading the already-updated state vars from LevelDB and applying further mutations plus producing a second distinct response unit — the AA's logic (and any funds/state it manages) is effectively executed twice for a single trigger unit.

### Citations

**File:** aa_composer.js (L59-88)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
```

**File:** aa_composer.js (L94-116)
```javascript
			var batch = kvstore.batch();
			readMcUnit(conn, mci, function (objMcUnit) {
				readUnit(conn, unit, function (objUnit) {
					var arrResponses = [];
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
							if (!objUnitProps.count_aa_responses)
								objUnitProps.count_aa_responses = 0;
							objUnitProps.count_aa_responses += arrResponses.length;
							var batch_start_time = Date.now();
							batch.write({ sync: true }, function(err){
								console.log("AA batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("AA composer: batch write failed: "+err);
								conn.query("COMMIT", function () {
									conn.release();
```

**File:** aa_composer.js (L1861-1862)
```javascript
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
```

**File:** storage.js (L2353-2374)
```javascript
		conn.query(
			"SELECT unit, level, latest_included_mc_index, main_chain_index, is_on_main_chain, is_free, is_stable, witnessed_level, headers_commission, payload_commission, sequence, timestamp, GROUP_CONCAT(address) AS author_addresses, COALESCE(witness_list_unit, unit) AS witness_list_unit, best_parent_unit, last_ball_unit, tps_fee, max_aa_responses, count_aa_responses, count_primary_aa_triggers, is_aa_response, version \n\
			FROM units \n\
			JOIN unit_authors USING(unit) \n\
			WHERE is_stable=1 AND main_chain_index>=? \n\
			GROUP BY +unit \n\
			ORDER BY +level", [top_mci],
			function(rows){
				rows.forEach(function(row){
					row.count_primary_aa_triggers = row.count_primary_aa_triggers || 0;
					row.bAA = !!row.is_aa_response;
					delete row.is_aa_response;
					row.tps_fee = row.tps_fee || 0;
					if (parseFloat(row.version) >= constants.fVersion4)
						delete row.witness_list_unit;
					delete row.version;
					row.author_addresses = row.author_addresses.split(',');
					assocStableUnits[row.unit] = row;
					if (!assocStableUnitsByMci[row.main_chain_index])
						assocStableUnitsByMci[row.main_chain_index] = [];
					assocStableUnitsByMci[row.main_chain_index].push(row);
				});
```
