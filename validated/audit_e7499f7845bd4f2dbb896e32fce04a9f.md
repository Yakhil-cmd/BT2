## Analog Found

### Title
Unhandled exception while processing a single AA trigger permanently jams the shared, mutex-locked AA-trigger queue for the entire network - ([File: aa_composer.js])

### Summary
The Sherlock report describes an ERC1155 deposit/rollover queue that is processed sequentially (LIFO/FIFO) and can be permanently DOSed because one entry's external call can revert, blocking all entries queued behind it. `ocore` has a structurally identical pattern: `handleAATriggers()` pulls all pending AA triggers and processes them one‑by‑one with `async.eachSeries` while holding the `'aa_triggers'` mutex for the whole batch [1](#0-0) . If processing of a single row throws instead of calling back, the loop never advances, the mutex is never released, and every trigger already queued (plus every future call to `handleAATriggers`, which is queued behind the held mutex) is blocked forever.

### Finding Description
`handleAATriggers()` selects all pending rows from the `aa_triggers` table (deterministic, ordered by `mci, level, unit, address`) and iterates them with `async.eachSeries`, wrapped in `mutex.lock(['aa_triggers'], ...)`; the mutex is only released in the final callback of the series [1](#0-0) .

Each row is handled by `handlePrimaryAATrigger`, which contains an unconditional `throw Error` that is not routed through the `cb`/`onDone` callback chain used by `async.eachSeries`: [2](#0-1) 

Deeper inside the same call chain, `handleTrigger`'s `validateAndSaveUnit` helper also throws unconditionally for several branches (`ifJointError`, `ifTransientError`, `ifNeedHashTree`, `ifNeedParentUnits`, `ifOkUnsigned`) instead of bouncing gracefully like the rest of `handleTrigger`'s error handling (`bounce(err)`): [3](#0-2) 

Unlike the many other error conditions in `handleTrigger`/`sendUnit` that are funneled through `bounce()` and therefore terminate only the single AA response gracefully (e.g. the extensive validation in the message-processing loop) [4](#0-3) , these specific assertions are "should never happen" throws with no bounce fallback. Because they execute inside the `async.eachSeries` iterator of `handleAATriggers`, throwing here does not call `cb()`/`onDone()` — it propagates as an uncaught exception in Node.js, which by default crashes the process, or (depending on where the throw occurs relative to already-scheduled async callbacks) can leave the surrounding `mutex.lock(['aa_triggers'], ...)` never unlocked.

`mutex.js` confirms that `unlock()` is the only way a lock is released and the queue advanced — if the `proc` supplied to `exec()` never calls `unlock`, the lock is held forever and any further job requiring the same key is queued indefinitely [5](#0-4) .

`handleAATriggers` is invoked deterministically by every full node whenever an MCI stabilizes with pending AA triggers, both from `main_chain.js`'s `handleAATriggers` trigger-insertion logic [6](#0-5)  and from `writer.js` right after each stabilization and during any further stabilization loop [7](#0-6) . Since AA execution is fully deterministic across the network, a trigger/AA definition that hits one of these unconditional throws will hit it identically on every full node at the same MCI.

### Impact Explanation
This is the direct analog of the reported queue DOS: a single malicious/edge-case AA response construction can permanently jam the shared, ordered `aa_triggers` processing queue, exactly as a single reverting ERC1155 receiver jams `mintDepositInQueue`/`mintRollovers`. Because the queue and the mutex protecting it are global (not per-AA, per-unit), the "attack" blocks every pending and future AA trigger for every AA and every user — not just the attacker's own — and since this logic runs identically on all full nodes, the effect is network-wide: AA responses stop being generated/applied, funds sent to any AA become frozen behind the jam, and — since `finishMarkMcIndexStable`/further stabilization depend on `handleAATriggers` completing before more MCIs can be marked stable and before the write lock is released — the network can become unable to make further progress confirming/stabilizing units that depend on AA processing.

### Likelihood Explanation
Reaching this bug class requires only posting a unit that triggers an AA (or a chain of secondary AA triggers) whose deterministic response-construction hits one of the unconditional `throw Error` paths instead of the `bounce()` path — no special privileges, hub/peer/node compromise, or network positioning are needed; only a self-posted trigger unit and/or a self-defined AA, both of which are fully within reach of any ordinary user/AA author. The severity is high because a single crafted unit is sufficient and the effect is global and persistent (queue is never automatically retried past the failing row).

### Recommendation
- Wrap every step inside `handleAATriggers`'s `async.eachSeries` iterator (and inside `handlePrimaryAATrigger`/`handleTrigger`/`validateAndSaveUnit`) so that unexpected internal errors are converted into a graceful `bounce()`/skip of that single trigger rather than an unhandled `throw` that stalls the iterator and the mutex.
- Ensure the `'aa_triggers'` mutex is always released (e.g., via `try/finally`-style guarantees around the batch) even if an individual row's processing fails unexpectedly, so one bad trigger cannot block all others.
- Add defensive handling so `validateAndSaveUnit`'s `ifJointError`/`ifTransientError`/`ifNeedHashTree`/`ifNeedParentUnits`/`ifOkUnsigned` branches cannot be reached by attacker-influenced conditions in production, and audit `handlePrimaryAATrigger`'s cache-consistency `throw Error(...unit not found in cache)` for whether it is reachable via race conditions in trigger ordering.

### Proof of Concept
1. Post a unit that triggers an AA whose deterministic execution (through `handleTrigger`/`sendUnit`, possibly chained into a secondary AA via `handleSecondaryTriggers`) constructs a response unit that fails one of the unconditional-throw checks in `validateAndSaveUnit` (e.g., `ifJointError`) rather than one of the many `bounce()`-guarded checks earlier in `sendUnit` [8](#0-7) .
2. Once this unit's MCI stabilizes, every full node calls `handleAATriggers()` [6](#0-5) [7](#0-6) , which locks `'aa_triggers'` and begins `async.eachSeries` over all pending trigger rows including the crafted one [1](#0-0) .
3. When the crafted row is processed, the unconditional `throw` fires inside `handlePrimaryAATrigger`'s call chain; `cb()`/`onDone()` is never invoked, so `unlock()` in `handleAATriggers` is never called [9](#0-8) .
4. Per `mutex.js`, the `'aa_triggers'` lock is now held indefinitely; all subsequent triggers (in this and every future batch, on every node) queue behind it and are never processed [5](#0-4) , freezing all AA fund flows and further stabilization-dependent progress network-wide.

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

**File:** aa_composer.js (L91-109)
```javascript
function handlePrimaryAATrigger(mci, unit, address, arrDefinition, arrPostedUnits, onDone) {
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
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
```

**File:** aa_composer.js (L1247-1279)
```javascript
		for (var i = 0; i < messages.length; i++){
			var message = messages[i];
			if (!isNonemptyObject(message))
				return bounce("message must be nonempty object");
			if (ValidationUtils.hasFieldsExcept(message, ['app', 'payload']))
				return bounce("unknown fields in message");
			if (typeof message.app !== 'string')
				return bounce("app must be a string");
			if (!aa_validation.aaApps.includes(message.app))
				return bounce("unsupported app: " + message.app);
			if (!['string', 'object'].includes(typeof message.payload) || message.payload === null)
				return bounce("payload must be string or object");
			if (message.app !== 'payment')
				continue;
			var payload = message.payload;
			if (!isNonemptyObject(payload))
				return bounce("payload must be nonempty object");
			if (ValidationUtils.hasFieldsExcept(payload, ['asset', 'outputs']))
				return bounce("unknown fields in payment payload");
			if (!Array.isArray(payload.outputs))
				return bounce("outputs must be array"); // empty array is okay
			if (!payload.outputs.every(o => ValidationUtils.isValidAddress(o.address)))
				return bounce("invalid addresses in outputs");
			if (payload.outputs.some(o => ValidationUtils.hasFieldsExcept(o, ['address', 'amount'])))
				return bounce("unknown fields in outputs");
			if ('asset' in payload && !(payload.asset === 'base' || ValidationUtils.isStringOfLength(payload.asset, constants.HASH_LENGTH)))
				return bounce("asset must be a string or omitted");
			// negative or fractional
			if (!payload.outputs.every(function (output) { return (isNonnegativeInteger(output.amount) || output.amount === undefined); }))
				return bounce("negative or fractional amounts");
			// filter out 0-outputs
			payload.outputs = payload.outputs.filter(function (output) { return (output.amount > 0 || output.amount === undefined); });
		}
```

**File:** aa_composer.js (L1800-1837)
```javascript
	function validateAndSaveUnit(objUnit, cb) {
		var objJoint = { unit: objUnit, aa: true, aa_mci: mci };
		validation.validate(objJoint, {
			ifJointError: function (err) {
				throw Error("AA validation joint error: " + err);
			},
			ifUnitError: function (err) {
				console.log("AA validation unit error: " + err);
				return cb(err);
			},
			ifTransientError: function (err) {
				throw Error("AA validation transient error: " + err);
			},
			ifNeedHashTree: function () {
				throw Error("AA validation unexpected need hash tree");
			},
			ifNeedParentUnits: function (arrMissingUnits) {
				throw Error("AA validation unexpected dependencies: " + arrMissingUnits.join(", "));
			},
			ifOkUnsigned: function () {
				throw Error("AA validation returned ok unsigned");
			},
			ifOk: function (objAAValidationState, validation_unlock) {
				if (objAAValidationState.sequence !== 'good')
					throw Error("nonserial AA");
				validation_unlock();
				objAAValidationState.bUnderWriteLock = true;
				objAAValidationState.conn = conn;
				objAAValidationState.batch = batch;
				objAAValidationState.initial_trigger_mci = mci;
				objAAValidationState.bDryRun = trigger_opts.bDryRun;
				writer.saveJoint(objJoint, objAAValidationState, null, function(err){
					if (err)
						throw Error('AA writer returned error: ' + err);
					cb();
				});
			}
		}, conn);
```

**File:** mutex.js (L43-86)
```javascript
function exec(arrKeys, proc, next_proc){
	arrLockedKeyArrays.push(arrKeys);
	console.log("lock acquired", arrKeys);
	var bLocked = true;
	proc(function unlock(unlock_msg) {
		if (!bLocked)
			throw Error("double unlock?");
		if (unlock_msg)
			console.log(unlock_msg);
		bLocked = false;
		release(arrKeys);
		console.log("lock released", arrKeys);
		if (next_proc)
			next_proc.apply(next_proc, arguments);
		handleQueue();
	});
}

function handleQueue(){
	console.log("handleQueue "+arrQueuedJobs.length+" items");
	for (var i=0; i<arrQueuedJobs.length; i++){
		var job = arrQueuedJobs[i];
		if (isAnyOfKeysLocked(job.arrKeys))
			continue;
		arrQueuedJobs.splice(i, 1); // do it before exec as exec can trigger another job added, another lock unlocked, another handleQueue called
		console.log("starting job held by keys", job.arrKeys);
		exec(job.arrKeys, job.proc, job.next_proc);
		i--; // we've just removed one item
	}
	console.log("handleQueue done "+arrQueuedJobs.length+" items");
}

function lock(arrKeys, proc, next_proc){
	if (arguments.length === 1)
		return new Promise(resolve => lock(arrKeys, resolve));
	if (typeof arrKeys === 'string')
		arrKeys = [arrKeys];
	if (isAnyOfKeysLocked(arrKeys)){
		console.log("queuing job held by keys", arrKeys);
		arrQueuedJobs.push({arrKeys: arrKeys, proc: proc, next_proc: next_proc, ts:Date.now()});
	}
	else
		exec(arrKeys, proc, next_proc);
}
```

**File:** main_chain.js (L1691-1723)
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
			}
		);
	}
```

**File:** writer.js (L724-759)
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
								if (arrStabilizedMcis.length > 0 && !err) {
									// try to stabilize more MCIs, run triggers and update tps fees after each
									console.log(`stabilized MCI ${arrStabilizedMcis.join(', ')}, trying to stabilize more`);
									while (true) {
										const conn = await db.takeConnectionFromPool();
										await conn.query("BEGIN");
										const batch = kvstore.batch();
										const { arrStabilizedMcis, bStabilizedAATriggers } = await main_chain.advanceMcStability(conn, batch, objUnit.unit);
										console.log(`additional stabilization result`, arrStabilizedMcis, bStabilizedAATriggers);
										if (arrStabilizedMcis.length > 1)
											throw Error(`additional stabilization resulted in more than one MCI: ${arrStabilizedMcis.join(', ')}`);
										await util.promisify(batch.write.bind(batch))({ sync: true });
										await conn.query("COMMIT");
										conn.release();
										if (arrStabilizedMcis.length === 0)
											break;
										if (bStabilizedAATriggers) {
											console.log(`executing AA triggers after additional stabilization`, arrStabilizedMcis);
											// every trigger takes its own db connection
											const aa_composer = require("./aa_composer.js");
											await aa_composer.handleAATriggers();
										}
```
