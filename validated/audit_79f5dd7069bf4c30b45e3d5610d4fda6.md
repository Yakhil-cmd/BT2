### Title
Attacker-controlled AA trigger processing time blocks the global write mutex, stalling network-wide unit confirmation - ([File: writer.js])

### Summary
The `aa_triggers` table is a defer-style queue: each stable unit that pays to an AA address inserts a row that is later drained by `aa_composer.handleAATriggers()`. This draining runs **inside the same global `['write']` mutex lock** that `writer.js` takes for every unit write, so any single AA trigger that is slow to execute stalls all subsequent unit writes network-wide — the same "defer queue blocks unrelated work" bug class as CVE-2023-38498/GHSA-wv29-rm3f-4g2j in Discourse.

### Finding Description
`writer.js:saveJoint()` acquires the process-wide `['write']` mutex before doing anything else: `const unlock = ... await mutex.lock(["write"]);` [1](#0-0) . This lock is only released at the very end of the write, **after** AA trigger processing completes: `if (bStabilizedAATriggers && !err) { ... await aa_composer.handleAATriggers(); ... }` followed by a `while (true)` loop that keeps calling `handleAATriggers()` again for every additional MCI that becomes stabilized, before finally calling `unlock()` [2](#0-1) .

`handleAATriggers()` itself takes a second, AA-specific mutex (`['aa_triggers']`) and processes every queued trigger **serially** with `async.eachSeries`, in deterministic order by `mci, level, unit, address`: [3](#0-2) . Each row is dequeued from the `aa_triggers` table, which is explicitly documented as "a queue... almost always empty and short-lived" [4](#0-3) , and rows are inserted transactionally whenever a unit becomes stable and pays to an AA address, in `main_chain.js:handleAATriggers()` (the MC-stability-time trigger-collector, not to be confused with the AA composer's drain function of the same name) [5](#0-4) .

Because `handlePrimaryAATrigger` → `handleTrigger` executes the AA's oscript/formula code, evaluates conditions, and can recursively trigger further "secondary" AAs, the total wall-clock time to drain the queue is proportional to the complexity and chain-length of whatever AAs a unit author chooses to trigger. Any unprivileged user can define an AA (address definition + `oscript`) with heavy formula computation or deep secondary-AA call chains and then post a single paying unit to it. Once that unit becomes stable, `handleAATriggers()` runs synchronously while holding the global `write` lock, so **no other unit — from any user, for any purpose — can be committed to the DAG** until that AA's entire chain of execution finishes.

This mirrors the Discourse defer-queue issue: a low-privileged actor enqueues a resource-heavy job into a shared serial queue that is required to drain before unrelated, higher-priority work (there: other multisite requests; here: unrelated unit writes) can proceed.

### Impact Explanation
While the `write` mutex is held, `saveJoint()` cannot be entered for any new unit from any peer, meaning the node cannot confirm/write any new units during that window. If an attacker crafts an AA with a long chain of secondary triggers or expensive formula evaluation (loops, large state variable manipulation, `foreach`, etc.) and repeatedly posts triggering units, they can keep extending the time the network's write path is blocked, degrading throughput and confirmation latency for the whole node — a network-availability impact ("a network unable to confirm new units") rather than a fund-loss issue. Because full nodes replicate the same DAG and the same AA execution rules deterministically, the same self-inflicted stall would occur on every full node processing that unit, amplifying the effect network-wide rather than being confined to a single operator's node.

### Likelihood Explanation
Reaching this path only requires: (1) defining an AA (unprivileged, anyone can post an address definition), and (2) posting a single unit that pays to it (unprivileged). No special role, hub/light-vendor trust, or node compromise is needed — it is a pure "malicious AA author + AA trigger sender" path, which is in scope. The main uncertainty is exactly how large the achievable per-trigger delay can be, since I could not fully confirm within this session whether `formula/evaluation.js` and `aa_composer.js` enforce a hard wall-clock or operation-count ceiling per AA execution (I found many `MAX_*`-style tokens in `constants.js`, `formula/validation.js`, and `aa_composer.js`, e.g. limits on state var length, response counts, and message counts, but did not have time to confirm whether any of them bound total *execution time* of a single trigger's cascade of secondary AA calls, as opposed to just object/size limits). If such limits meaningfully cap total single-trigger processing time, the achievable DoS window is bounded per unit (though still repeatable across many units); if they do not bound cumulative computational cost of chained secondary triggers, the delay could be substantial.

### Recommendation
- Decouple AA-trigger execution from the unit-write critical section: release the `write` lock (or use a narrower lock scope) before invoking `aa_composer.handleAATriggers()`, and let trigger execution proceed under only the `aa_triggers` lock so unrelated unit writes are not blocked.
- Enforce a strict wall-clock or operation-count budget for the full "primary trigger + all secondary triggers" cascade coming from a single stabilized unit, independent of per-formula operation caps, and bounce/abort trigger chains that exceed it.
- Confirm and, if necessary, tighten existing `MAX_*` limits in `constants.js`/`formula/validation.js` so they bound cumulative cascade cost, not just individual formula/message size.
- Add monitoring/alerting on `handleAATriggers()` duration so unusually expensive trigger chains are visible in production.

### Proof of Concept
1. Deploy an AA `A` whose `oscript`/formula performs a computation-heavy operation (e.g., a large bounded loop via `foreach`/recursive secondary AA calls) sized just under whatever per-formula limits exist, and which triggers a chain of `N` secondary AAs `A→B→C→...`, each doing similar heavy work.
2. Post a unit paying to `A`; wait for it to stabilize.
3. When `main_chain.js`'s stability routine marks the MCI stable, it inserts a row into `aa_triggers` [6](#0-5) .
4. `writer.js` then calls `aa_composer.handleAATriggers()` while still holding the `['write']` mutex acquired at the top of `saveJoint()` [1](#0-0) , [7](#0-6) .
5. During the entire cascade of primary + secondary trigger execution (`handlePrimaryAATrigger`/`handleTrigger`), any concurrent unit submitted by any other user cannot be saved, because `mutex.lock(["write"])` in `saveJoint()` queues behind the still-held lock.
6. Repeating this with multiple such units sustains the stall, delaying confirmation of unrelated transactions across the node.

### Citations

**File:** writer.js (L34-34)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
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

**File:** initial-db/byteball-mysql.sql (L805-815)
```sql
-- the table is a queue, it is almost always empty and any entries are short-lived
-- INSERTs are wrapped in the same SQL transactions that write the triggering units
-- secondary triggers are not written here
CREATE TABLE aa_triggers (
	mci INT NOT NULL,
	unit CHAR(44) NOT NULL,
	address CHAR(32) NOT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (mci, unit, address),
	FOREIGN KEY (address) REFERENCES aa_addresses(address)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
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
