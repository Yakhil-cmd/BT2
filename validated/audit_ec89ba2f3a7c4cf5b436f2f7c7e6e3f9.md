### Title
Unhandled `throw Error()` inside `handleTrigger()`/`updateStorageSize()` can crash the shared `aa_triggers` queue processing loop, freezing AA fund/state updates for the whole node - (File: aa_composer.js)

### Summary
`handleAATriggers()` processes every pending row of the `aa_triggers` table — a system-wide, first-in-first-out queue shared by *all* AAs and *all* trigger senders — with `async.eachSeries`, invoking `handlePrimaryAATrigger()` → `handleTrigger()` for each row in a deterministic order. [1](#0-0)  Several code paths reachable while composing an AA response `throw Error(...)` instead of returning an error through the normal callback/`bounce()` path, e.g. `updateStorageSize()`'s `if (new_storage_size < 0) throw Error("storage size would become negative: " + new_storage_size);`. [2](#0-1)  A synchronous `throw` inside this deeply nested callback chain is not caught anywhere in the chain (there is no try/catch around `handleTrigger`/`handlePrimaryAATrigger`/`handleAATriggers`), so it propagates as an uncaught exception, which in Node.js terminates the process.

### Finding Description
`aa_triggers` is documented as "the table is a queue" that is processed strictly in commit order (`ORDER BY aa_triggers.mci, level, aa_triggers.unit, address`). [3](#0-2)  Any unprivileged user can add an entry to this queue simply by sending a payment/message to any deployed AA address; `main_chain.js`'s `handleAATriggers()` inserts a row for every unit paying an AA once its MCI stabilizes. [4](#0-3)  `stabilizeMci()`/`saveJoint()` then call `aa_composer.handleAATriggers()` synchronously as part of normal unit-stabilization flow, so the queue is drained by the node's core write path, not an isolated worker. [5](#0-4) [6](#0-5) 

Inside `handleTrigger()`, after formula evaluation, state-var updates are persisted through `updateStorageSize()`, which computes `new_storage_size = storage_size + delta_storage_size` from the AA's declared state-var writes and unconditionally `throw`s if the result is negative, instead of surfacing the condition through the `cb(err)` error-handling convention used everywhere else in the same function (e.g. the sibling checks `return cb("invalid new value of state var …")` and `return cb("state var value too long …")` a few lines above it use the safe pattern, while this one line does not). [7](#0-6)  Because `delta_storage_size` is derived from state-var deletions/updates whose sizes are computed from `state.original_old_value` and `state.value` (values that ultimately originate from oscript execution influenced by attacker-supplied trigger data, e.g. `trigger.data`), a caller can compose a trigger that drives an AA into a state-var accounting edge case that this line does not defensively convert to a normal bounce, throwing instead.

Because `handleAATriggers()` walks the whole `aa_triggers` table for every AA on the network in one `async.eachSeries` loop and this exception happens synchronously inside the callback chain (not passed to `cb(err)`), the exception bubbles up uncaught through `handlePrimaryAATrigger` → `handleAATriggers` → `main_chain.stabilizeMci`/`writer.saveJoint`, crashing the node process. Since the triggering row is *not* deleted from `aa_triggers` before the crash (deletion happens later, after `handleTrigger`'s callback completes: `conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", …)` runs only inside the `handleTrigger` success callback), restarting the node causes `handleAATriggers()` to immediately re-process the same poisoned row and crash again, producing a persistent crash loop that halts AA-trigger processing for the entire node until an operator manually intervenes (e.g., deleting the row or patching the code). [8](#0-7) 

This mirrors the reported Y2K bug class exactly: a single malicious, low-cost queue entry (there is no extra cost beyond a normal payment to the AA) permanently DOSes a shared FIFO queue that other unrelated participants depend on to have their funds/state processed, because the queue processor has no way to skip a poisoned entry and continue.

### Impact Explanation
A crash/crash-loop in `handleAATriggers()` freezes processing of *every* AA trigger on the node — not just the attacker's — including any AAs holding user funds, until the poisoned row is manually removed from the database. This satisfies "AA fund loss or freezing" and, for witnesses/validators running this code, contributes to "a network unable to confirm new units" since stabilization flow (`stabilizeMci`, `saveJoint`) is blocked on `handleAATriggers()` completing.

### Likelihood Explanation
Reaching the exact `new_storage_size < 0` branch requires crafting an AA (or interacting with an existing permissively-designed AA) whose state-var deletion/update accounting can be pushed negative by trigger-controlled state changes — this needs some knowledge of the target AA's oscript logic and possibly specific state history, so likelihood is moderate rather than trivial. However, the broader class of "unhandled `throw Error` reachable from trigger-controlled formula/state paths inside `handleTrigger`" is structural: many of the 30+ `throw Error(...)` statements in `aa_composer.js` sit in code paths downstream of trigger-controlled data, and the fix for a well-formed test case doesn't fix the general pattern.

### Recommendation
Convert the storage-size-negative check (and any other `throw Error(...)` in `handleTrigger()`/`updateStorageSize()` that depends on state derived from trigger data) into the same `cb(err)`/`bounce(err)` error propagation pattern already used for sibling checks in the same function, so a bad/edge-case trigger causes only that trigger's response to bounce rather than crashing the whole trigger-processing loop. Additionally, wrap `handleAATriggers`'s per-row processing (`handlePrimaryAATrigger`) so that any residual uncaught exception for a single row logs the error, deletes/skips that row, and continues with the remaining queue instead of letting the exception propagate to the process level.

### Proof of Concept
Conceptual PoC (exact oscript needed to hit the negative-storage-size branch was not verified against a running node in this review, since only source inspection was performed):
1. Deploy an AA that writes/deletes a state var whose declared "old value" size bookkeeping can be manipulated via trigger-supplied `trigger.data` (e.g. an AA that stores `var[trigger.data.key] = trigger.data.value` and later deletes it based on attacker-chosen size assumptions).
2. Send a sequence of triggers that cause `state.original_old_value` accounting in `updateStorageSize()` to diverge from actual `storage_size`, producing `delta_storage_size` more negative than the current `storage_size`.
3. Once such a trigger unit is posted and its MCI stabilizes, it is enqueued into `aa_triggers` and processed by `handleAATriggers()`; hitting the `new_storage_size < 0` branch throws synchronously, which is not caught anywhere in the `handleAATriggers → handlePrimaryAATrigger → handleTrigger` call chain, crashing the node process while the row remains in `aa_triggers`, causing a crash loop on restart.

### Citations

**File:** aa_composer.js (L59-89)
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
}
```

**File:** aa_composer.js (L101-103)
```javascript
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
```

**File:** aa_composer.js (L1544-1565)
```javascript
			else {
				try {
					var newSize = getValueSize(state.value);
				}
				catch (e) {
					console.log("failed to get size of new value of state var " + var_name + ": ", e);
					return cb("invalid new value of state var " + var_name);
				}
				if (newSize > constants.MAX_STATE_VAR_VALUE_LENGTH)
					return cb(`state var value too long: ${newSize}`);
				if (state.original_old_value !== undefined)
					delta_storage_size += newSize - getValueSize(state.original_old_value);
				else
					delta_storage_size += var_name.length + newSize;
			}
		}
		console.log('storage size = ' + storage_size + ' + ' + delta_storage_size + ', byte_balance = ' + byte_balance);
		var new_storage_size = storage_size + delta_storage_size;
		if (new_storage_size < 0)
			throw Error("storage size would become negative: " + new_storage_size);
		if (byte_balance < new_storage_size && new_storage_size > FULL_TRANSFER_INPUT_SIZE && mci >= constants.aaStorageSizeUpgradeMci)
			return cb("byte balance " + byte_balance + " would drop below new storage size " + new_storage_size);
```

**File:** main_chain.js (L1262-1276)
```javascript
// marks the MCI stable, executes triggers, and updates tps fees
async function stabilizeMci(mci) {
	const conn = await db.takeConnectionFromPool();
	await conn.query("BEGIN");
	const batch = kvstore.batch();
	const count_aa_triggers = await markMcIndexStable(conn, batch, mci);
	await util.promisify(batch.write.bind(batch))({ sync: true });
	await conn.query("COMMIT");
	conn.release();
	if (count_aa_triggers > 0) {
		console.log(`executing ${count_aa_triggers} AA triggers after stabilizing MCI ${mci}`);
		// every trigger takes its own db connection
		const aa_composer = require("./aa_composer.js");
		await aa_composer.handleAATriggers();
	}
```

**File:** main_chain.js (L1691-1720)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
			function (rows) {
				count_aa_triggers = rows.length;
				if (rows.length === 0)
					return finishMarkMcIndexStable();
				var arrValues = rows.map(function (row) {
					return "("+mci+", "+conn.escape(row.unit)+", "+conn.escape(row.address)+")";
				});
				conn.query("INSERT INTO aa_triggers (mci, unit, address) VALUES " + arrValues.join(', '), function () {
					finishMarkMcIndexStable();
					// now calling handleAATriggers() from write.js
				//	process.nextTick(function(){ // don't call it synchronously with event emitter
				//		eventBus.emit("new_aa_triggers"); // they'll be handled after the current write finishes
				//	});
				});
```

**File:** writer.js (L724-737)
```javascript
								if (bStabilizedAATriggers && !err) {
									console.log(`executing AA triggers`);
									const aa_composer = require("./aa_composer.js");
									await aa_composer.handleAATriggers();

									if (arrStabilizedMcis[0] >= constants.v4UpgradeMci) {
										// get a new connection to write tps fees
										const conn = await db.takeConnectionFromPool();
										await conn.query("BEGIN");
										await storage.updateTpsFees(conn, arrStabilizedMcis);
										await conn.query("COMMIT");
										conn.release();
									}
								}
```
