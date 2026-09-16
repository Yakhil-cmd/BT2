## Title
An attacker-triggered exception during AA-trigger processing permanently stalls the shared `aa_triggers` queue for all other AAs - (File: `aa_composer.js`)

### Summary
`handleAATriggers()` processes **all** pending AA triggers system-wide in a single `async.eachSeries` loop while holding a global `mutex.lock(['aa_triggers'], ...)`. A trigger row is deleted from the `aa_triggers` table only after its entire `handleTrigger()` call chain successfully calls back into `onDone()`. If processing of a single (attacker-crafted) trigger throws or never completes instead of gracefully bouncing, the loop never advances to the remaining rows and the mutex is never released, which blocks every other user's pending AA trigger from ever being processed — the same "one bad actor blocks the whole batch" bug class as the referenced report, but applied to Obyte's AA trigger queue instead of an ERC1155 mint queue.

### Finding Description
`handleAATriggers()` selects *every* row from `aa_triggers` (a shared, network-wide queue, not per-AA) and iterates them with `async.eachSeries`, only calling `unlock()` in the final callback after the entire series completes: [1](#0-0) 

Each row is handled by `handlePrimaryAATrigger()`, which only removes the row from `aa_triggers` after `handleTrigger()` invokes its completion callback: [2](#0-1) 

`handleTrigger()` and its many nested helper functions (`getTrigger`, `updateInitialAABalances`, `handleSecondaryTriggers`, `finish`, etc.) contain numerous synchronous `throw Error(...)` invariant checks that are reachable from attacker-controlled AA definitions, trigger data, or state-formula evaluation results (e.g. malformed/edge-case payloads reaching `getTrigger`'s "no outputs to" check, `handleTrigger`'s "bad AA definition"/"base AA not found" checks, or `updateInitialAABalances`'s "AA not found?" check), for example: [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

Because these are plain synchronous throws inside asynchronous DB/callback continuations (not passed through the `cb`/`onDone` error-handling path that leads to a graceful `bounce()`), they either crash the node process outright or leave the `async.eachSeries` iteratee permanently unresolved. In both cases, the affected trigger row is **never deleted** from `aa_triggers`, and `unlock()` in `handleAATriggers()` is never reached.

Crucially, `handleAATriggers()` is awaited synchronously from the unit-writing and stabilization critical path: [7](#0-6) [8](#0-7) 

so once the `aa_triggers` mutex is stuck, no further AA triggers — belonging to any other, honest user or AA — can ever be processed again on that node. On restart, the same poisoned row is selected first (`ORDER BY aa_triggers.mci, level, ...`), reproducing the same crash/hang deterministically.

### Impact Explanation
A single malicious AA (which anyone can permissionlessly deploy and trigger by sending a payment to it) that reaches one of these unhandled throw paths can permanently freeze processing of the shared `aa_triggers` queue. This blocks/bounces-nothing for every other pending or future AA trigger on that node — analogous to how the referenced report's revert in a shared queue prevented minting for all other depositors. Because trigger execution is consensus-relevant (feeds into unit/response generation and MC stabilization), this can cause node disagreement on AA outcomes or a full halt of AA-driven fund movement/state updates network-wide, i.e. AA fund freezing and inability to confirm further AA-dependent units.

### Likelihood Explanation
Likelihood is limited by needing to find/craft a specific attacker-reachable input that triggers one of these unguarded `throw Error` invariant checks rather than the graceful `bounce()` path — this requires careful analysis of `handleTrigger`'s state machine, but the attack surface is large (dozens of unguarded throws in the trigger-processing call graph) and the attacker only needs unprivileged ability to post an AA definition and send it a trigger payment, which is freely available to anyone.

### Recommendation
Wrap the entire per-trigger processing pipeline (`handlePrimaryAATrigger`/`handleTrigger` and all nested helpers) in a top-level try/catch (or convert internal invariant violations into calls to `bounce()`/`cb(err)` instead of `throw`), ensure `handleAATriggers()`'s `unlock()`/`onDone()` always fire even when a single row's processing fails, and delete/quarantine any poison-pill trigger row (or skip it and continue with the remaining rows) rather than letting failures block the entire shared queue indefinitely.

### Proof of Concept
1. Deploy an AA definition designed so that, during `handleTrigger()` execution, a code path reaches one of the unguarded `throw Error(...)` statements in `aa_composer.js` (e.g. crafting inputs to `handleSecondaryTriggers`, `updateInitialAABalances`, or the `base_aa` redirection logic) instead of following the normal `bounce()` error flow.
2. Send a payment (trigger) to this AA once it is stable; `main_chain.js`'s stabilization inserts the row into `aa_triggers` and invokes `aa_composer.handleAATriggers()`.
3. The thrown exception occurs before `handlePrimaryAATrigger`'s `DELETE FROM aa_triggers` (`aa_composer.js:102`) executes, so the row is never removed and `unlock()` at `aa_composer.js:82` is never reached.
4. Any subsequent unit that stabilizes and triggers another (honest) AA calls `handleAATriggers()` again via `writer.js:727/758` or `main_chain.js:1275`; this call queues forever on the still-locked `['aa_triggers']` mutex, so no AA on the network is ever processed again on that node, and the poisoned row is re-selected first on every restart.

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

**File:** aa_composer.js (L91-106)
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
```

**File:** aa_composer.js (L394-396)
```javascript
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
```

**File:** aa_composer.js (L424-425)
```javascript
	if (arrDefinition[0] !== 'autonomous agent')
		throw Error('bad AA definition ' + arrDefinition);
```

**File:** aa_composer.js (L531-534)
```javascript
					conn.query("SELECT storage_size FROM aa_addresses WHERE address=?", [address], function (rows) {
						if (rows.length === 0)
							throw Error("AA not found? " + address);
						storage_size = rows[0].storage_size;
```

**File:** aa_composer.js (L1718-1719)
```javascript
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
```

**File:** writer.js (L720-737)
```javascript
								if (arrStabilizedMcis.length > 0 && (bInLargerTx || objValidationState.bUnderWriteLock))
									throw Error(`saveJoint stabilized an MCI while in larger tx or under write lock`);
								if (arrStabilizedMcis.length > 1)
									throw Error(`saveJoint stabilized more than one MCI: ${arrStabilizedMcis.join(', ')}`);
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
