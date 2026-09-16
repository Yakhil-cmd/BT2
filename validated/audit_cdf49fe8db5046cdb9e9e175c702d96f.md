Confirmed: `saveJoint()` in `writer.js` acquires the global `write` mutex lock at the very top [1](#0-0)  and does not release it (`unlock()`) until after all triggered AA processing completes, including calls to `aa_composer.handleAATriggers()` [2](#0-1)  and even further chained triggers from additional stabilized MCIs in a `while(true)` loop [3](#0-2) . This confirms that AA trigger execution for a whole batch happens synchronously while blocking all further unit writes.

### Title
Unbounded, unbatched AA-trigger processing during MCI stabilization can stall the `write` mutex and halt confirmation of new units - (File: main_chain.js, aa_composer.js, writer.js)

### Summary
When an MCI becomes stable, `markMcIndexStable()`'s inner `handleAATriggers()` selects **every** trigger unit that pays to an AA address within that MCI in a single unbounded query and bulk-inserts them all into the `aa_triggers` queue table [4](#0-3) . Immediately afterward, `aa_composer.handleAATriggers()` drains the **entire** `aa_triggers` table for that MCI via a single `async.eachSeries` loop with no batch/limit argument, calling `handlePrimaryAATrigger` for each row sequentially [5](#0-4) . This mirrors the reported `Voter::_processPendingRemovals()` pattern: a pending-work array/queue that grows from unprivileged user actions and is later processed in one unbounded pass with no batching, instead of being chunked across multiple calls.

### Finding Description
Any unprivileged unit poster can pay a tiny output to an AA address; each such payment queues one row in `aa_triggers` once its MCI stabilizes [6](#0-5) . Because `handleAATriggers()` in `main_chain.js` has no cap on `rows.length` (no equivalent of a "too many triggers per MCI" limit was found in this function), an attacker can post an arbitrarily large number of cheap units, all paying an output to one or many AA addresses, all confirmed within a single MCI.

When that MCI stabilizes, `stabilizeMci()` / `markMcIndexStable()` inserts all matched trigger rows at once and then calls `aa_composer.handleAATriggers(onDone)` [7](#0-6) . `handleAATriggers()` fetches **all** queued rows (`ORDER BY aa_triggers.mci, level, ...`) with no `LIMIT`/batch parameter and processes them one-by-one with `async.eachSeries`, each iteration doing multiple DB round-trips and a full AA execution via `handlePrimaryAATrigger` [8](#0-7) . Crucially, this entire drain happens **while the global `write` mutex is still held** by the `saveJoint()` call that originally stabilized the MCI — `unlock()` for that mutex is only invoked after `await aa_composer.handleAATriggers()` (and any further chained stabilizations) complete [9](#0-8) .

Unlike the Solidity gas-limited example, this cannot literally revert with an out-of-gas error, but the effect is analogous: an attacker-inflated, unbounded queue is processed in one non-interruptible pass holding the `write` lock, so no other unit (from anyone) can be validated/written to the DAG until the attacker-induced backlog of AA triggers finishes executing. If the attacker keeps growing the backlog faster than it can be drained (e.g., by targeting AAs with more complex logic per trigger, or simply keeping many cheap trigger outputs queued across MCIs), the node is effectively unable to confirm new units for extended periods, which is a network-wide liveness impact substantially similar to the reported unbounded pending-removals DoS.

### Impact Explanation
While `write` is locked, the node cannot accept or persist any other units — new payments, AA calls, and asset transfers all stall. Because trigger processing is O(number of queued triggers) with no batching, an attacker who can cheaply and repeatedly generate qualifying trigger outputs can grow this backlog, extending the lock-held time without bound and degrading confirmation throughput/liveness for all users, not just the attacker's own transactions.

### Likelihood Explanation
Reaching this path only requires posting ordinary payment units with outputs to AA addresses — a fully unprivileged action available to any unit poster, with cost bounded by ordinary network/byte fees (no special privilege, and no obvious per-MCI trigger cap was found in `main_chain.js`'s `handleAATriggers()`). The main mitigating factor is the cost of unit fees and per-unit throughput limits imposed by the TPS-fee mechanism, which raises the economic cost of flooding but does not architecturally cap the number of triggers processed in one unbatched pass.

### Recommendation
Introduce a batch size limit in `main_chain.js`'s `handleAATriggers()`/`markMcIndexStable()` and in `aa_composer.js`'s `handleAATriggers()` so that only a bounded number of queued AA triggers are processed per invocation while holding the `write` lock, re-queuing and yielding (releasing/re-acquiring the lock, or scheduling continuation) for the remainder — analogous to adding a `batch` argument to `Voter::_processPendingRemovals()` in the referenced report.

### Proof of Concept
1. Attacker composes and posts many cheap units, each with a tiny output to a target AA address, so all of them land in the same not-yet-stable MCI.
2. Once that MCI is confirmed stable, `markMcIndexStable()`'s `handleAATriggers()` bulk-inserts all matching trigger rows into `aa_triggers` [6](#0-5) .
3. `aa_composer.handleAATriggers()` drains the full unbatched set via `async.eachSeries`, executing one full AA trigger per row sequentially [8](#0-7) , all while `saveJoint()`'s `write` mutex remains held [9](#0-8) .
4. With enough queued triggers (or if the targeted AAs themselves are computationally heavy), the drain time grows arbitrarily large, blocking every other unit write on the node for that duration.

**Note on verification depth:** I was not able to find, within the index, any explicit per-MCI cap on the number of AA triggers inserted/processed (searches for `MAX_AA_TRIGGERS`, `too many triggers` returned only unrelated `main_chain.js` matches for terms like `count_aa_triggers`, which is just a counter, not a limit). If such a limit exists elsewhere in the codebase (e.g., enforced indirectly via `MAX_MESSAGES_PER_UNIT`, TPS fee throttling, or a limit not captured by the index), it would reduce or eliminate the severity of this finding. Given index size limits, some file contents may not be fully available — a full audit of `main_chain.js` and `aa_composer.js` in a live Devin session would be advisable to confirm whether any such cap exists before treating this as fully validated.

### Citations

**File:** writer.js (L34-35)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);
```

**File:** writer.js (L720-776)
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
										if (arrStabilizedMcis[0] >= constants.v4UpgradeMci) {
											console.log(`updating tps fees after additional stabilization`, arrStabilizedMcis);
											// get a new connection to write tps fees
											const conn = await db.takeConnectionFromPool();
											await conn.query("BEGIN");
											await storage.updateTpsFees(conn, arrStabilizedMcis);
											await conn.query("COMMIT");
											conn.release();
										}
									}
								}
								if (onDone)
									onDone(err);
								count_writes++;
								if (conf.storage === 'sqlite')
									updateSqliteStats(objUnit.unit);
								unlock();
```

**File:** main_chain.js (L1263-1276)
```javascript
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
