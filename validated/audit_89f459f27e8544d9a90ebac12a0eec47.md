### Title
Unlocked concurrent execution of `dryRunPrimaryAATrigger` races with real AA-trigger execution on shared in-memory caches and `aa_balances` - ([File: aa_composer.js])

### Summary
`aa_composer.dryRunPrimaryAATrigger()` runs a *real* trigger execution (real DB connection, real `UPDATE aa_balances`, real mutation of the module-level in-memory caches used by the actual consensus path) but is reachable and executed without holding the same mutex keys (`"write"` / `"aa_triggers"`) that protect the genuine, state-committing trigger-execution path. This mirrors the CVE-2014-9914 bug class: a routine that mutates shared internal data structures runs concurrently with another routine that assumes exclusive access to the same structures, because of incorrect/mismatched locking assumptions between the two code paths.

### Finding Description
Real (committing) AA trigger execution always happens while the module-level `"write"` mutex is held: `writer.saveJoint` acquires it at [1](#0-0) , and `aa_composer.handleAATriggers`, which is invoked from inside `saveJoint` while that same lock is still held, additionally serializes itself with `mutex.lock(['aa_triggers'], ...)` [2](#0-1) . Because `handleTrigger` mutates shared, un-scoped module globals such as `storage.assocUnstableUnits`, `storage.last_aa_response_id`, and directly issues `UPDATE aa_balances` on the AA’s address [3](#0-2) , the whole trigger chain (including nested/secondary triggers, [4](#0-3) ) is expected to run under exclusive access.

`dryRunPrimaryAATrigger`, however, opens its own DB connection, runs `handleTrigger` for real (not a simulation limited to memory), and only rolls back the SQL transaction at the very end: [5](#0-4) . This function is reachable in two ways without the `"write"`/`"aa_triggers"` locks:

1. From `network.js` when a plain unit is received/posted and happens to pay an AA address (`conf.bDryRunNewTriggers`), guarded only by the `'handleJoint'` key, a different lock from `"write"`/`"aa_triggers"`: [6](#0-5) .
2. From the `'light/dry_run_aa'` network request handler, servable to any connected (light) peer, with **no** lock at all: [7](#0-6) .

Meanwhile, real stabilization-triggered AA execution runs concurrently under `"write"`/`"aa_triggers"` from `writer.saveJoint`: [8](#0-7)  and again in the “stabilize more MCIs” loop: [9](#0-8) .

Since these two code paths use disjoint mutex keys, Node’s event loop can interleave them across their many `await`/callback yield points inside `handleTrigger` (e.g., every `conn.query` call in `updateInitialAABalances`). The dry-run path additionally performs cache cleanup that touches the same shared structures the real path relies on: `revertResponsesInCaches` calls `storage.forgetUnit` and `storage.fixIsFreeAfterForgettingUnit`, mutating `storage.assocUnstableUnits` and `is_free` flags for units unrelated to the dry run itself if the dry run’s unit IDs happen to collide/interleave with genuinely unstable units of the same AA: [10](#0-9) ; and it also increments the shared `storage.last_aa_response_id` counter used by real writes: [11](#0-10) .

### Impact Explanation
If a dry run (triggered by an ordinary posted unit or by an unauthenticated `light/dry_run_aa` request) interleaves with a genuine trigger execution for the same AA address, the two executions can read/mutate the same `aa_balances` row, the same `storage.assocUnstableUnits` entries, and the same `storage.last_aa_response_id` counter concurrently. This can corrupt the balance snapshot seen by the real execution (leading to an AA crediting/debiting an incorrect amount — fund loss or inflation for the AA), or corrupt `is_free`/unstable-unit bookkeeping that different full nodes rely on to agree on unit validity and stability, producing node disagreement on validity/stability of the affected DAG region. This satisfies the “AA fund loss or freezing” / “node disagreement on validity or stability” impact bar.

### Likelihood Explanation
Triggering a dry run costs nothing more than sending an ordinary payment to any AA address (posted unit path) or, more directly, issuing a `light/dry_run_aa` request as any connected light peer, which requires no special privilege — it is a documented light-wallet API. Winning the race requires the target AA to also be undergoing genuine, natural stabilization-triggered execution at roughly the same time, which an attacker can increase the odds of by repeatedly triggering the target AA and simultaneously flooding it with dry-run requests. This is a timing-dependent race rather than a deterministic bug, so likelihood is moderate rather than certain.

### Recommendation
Make `dryRunPrimaryAATrigger` (and the `light/dry_run_aa` handler) acquire the same `"write"` (or `"aa_triggers"`) mutex used by the real, committing trigger-execution path before running `handleTrigger`, so dry runs and real executions are always mutually exclusive with respect to the shared in-memory caches (`assocUnstableUnits`, `last_aa_response_id`, balances) and the `aa_balances` table, exactly as `writer.saveJoint`/`handleAATriggers` already do for each other.

### Proof of Concept
Conceptual PoC (cannot be executed without the running node, provided to describe the exploitation window):
1. Deploy an AA whose trigger reads/writes its own `aa_balances` and asset state.
2. Continuously send it real trigger units so that it is frequently undergoing genuine, stabilization-driven execution inside `handleAATriggers`/`writer.saveJoint` (holding `"write"`/`"aa_triggers"`).
3. In parallel, as an unauthenticated light client, flood the hub with `light/dry_run_aa` requests (`network.js:3939`) targeting the same AA address; this path takes no lock at all.
4. Because the two paths use disjoint/no locks, their `conn.query` interleavings on `aa_balances` and their mutations to `storage.assocUnstableUnits`/`storage.last_aa_response_id` can race, causing the real execution to observe a balance/state snapshot corrupted by the concurrent dry run, or vice-versa.

Note: I was not able to directly execute/reproduce the timing race in this environment (no runtime access); the above is derived from static analysis of the locking keys used across `writer.js`, `aa_composer.js`, and `network.js`, which is a strong (but not dynamically confirmed) analog to the CVE’s "incorrect expectations about locking during multithreaded access" root cause.

### Citations

**File:** writer.js (L34-34)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
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

**File:** writer.js (L738-770)
```javascript
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

**File:** aa_composer.js (L272-306)
```javascript
function dryRunPrimaryAATrigger(trigger, address, arrDefinition, onDone) {
	if (!onDone)
		return new Promise(resolve => dryRunPrimaryAATrigger(trigger, address, arrDefinition, resolve));
	console.log('dry run', address, trigger);
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = conf.bLight ? lightBatch : kvstore.batch();
			readLastStableMcUnit(conn, function (mci, objMcUnit) {
				trigger.unit = constants.GENESIS_UNIT; // objMcUnit.unit; // might cause duplicate trigger_unit in aa_triggers if objMcUnit is already a real trigger
				if (!trigger.address)
					trigger.address = objMcUnit.authors[0].address;
				trigger.initial_address = trigger.address;
				trigger.initial_unit = trigger.unit;
				var fPrepare = function (cb) {
					insertFakeOutputsIntoMcUnit(conn, objMcUnit, trigger.outputs, address, cb);
				};
				fPrepare(function () {
					var arrResponses = [];
					handleTrigger({
						bDryRun: true, // suppress events for a unit that will be rolled back
						conn, batch, trigger, params: {}, stateVars: {}, arrDefinition, address, mci, objMcUnit, bSecondary: false, arrResponses,
						onDone: function () {
							revertResponsesInCaches(arrResponses);
							batch.clear();
							conn.query("ROLLBACK", function () {
								conn.release();
								onDone(arrResponses);
							});
						},
					});
				});
			});
		});
	});
}
```

**File:** aa_composer.js (L493-524)
```javascript
		conn.query(
			"SELECT asset, balance FROM aa_balances WHERE address=?",
			[address],
			function (rows) {
				var arrQueries = [];
				// 1. update balances of existing assets
				rows.forEach(function (row) {
					if (constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
						reintroduceBalanceBug(address, row);
					if (!trigger.outputs[row.asset]) {
						objValidationState.assocBalances[address][row.asset] = row.balance;
						return;
					}
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

**File:** aa_composer.js (L1628-1637)
```javascript
		conn.query(
			"INSERT INTO aa_responses (mci, trigger_address, aa_address, trigger_unit, bounced, response_unit, response) \n\
			VALUES (?, ?,?,?, ?,?,?)",
			[mci, trigger.address, address, trigger.unit, bBouncing ? 1 : 0, response_unit, JSON.stringify(response)],
			function (res) {
				if (!trigger_opts.bDryRun)
					storage.last_aa_response_id = res.insertId;
				cb();
			}
		);
```

**File:** aa_composer.js (L1702-1741)
```javascript
	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
```

**File:** aa_composer.js (L1900-1916)
```javascript
function revertResponsesInCaches(arrResponses) {
	// remove the rolled back units from caches and correct is_free of their parents if necessary
	console.log('will revert responses ' + JSON.stringify(arrResponses, null, '\t'));
	var arrResponseUnits = [];
	arrResponses.forEach(function (objAAResponse) {
		if (objAAResponse.response_unit)
			arrResponseUnits.push(objAAResponse.response_unit);
	});
	console.log('will revert response units ' + arrResponseUnits.join(', '));
	if (arrResponseUnits.length > 0) {
		var first_unit = arrResponseUnits[0];
		var objFirstUnit = storage.assocUnstableUnits[first_unit];
		var parent_units = objFirstUnit.parent_units;
		arrResponseUnits.forEach(storage.forgetUnit);
		storage.fixIsFreeAfterForgettingUnit(parent_units);
	}
}
```

**File:** network.js (L1271-1281)
```javascript
					if (conf.bDryRunNewTriggers && !conf.bLight && !objJoint.ball && objValidationState.count_primary_aa_triggers) {
						const outputAddresses = objJoint.unit.messages
							.filter(msg => msg.app === 'payment')
							.reduce((acc, msg) => acc.concat(msg.payload.outputs.map(output => output.address)), []);
						const rows = await db.query("SELECT address, definition FROM aa_addresses WHERE address IN (?)", [outputAddresses]);
						for (let { address, definition } of rows) {
							console.log(`dry run trigger for AA address ${address} in submitted unit ${unit}`);
							const trigger = aa_composer.getTrigger(objJoint.unit, address);
							// if it would crash, let it crash now, not when we execute the trigger for real
							await aa_composer.dryRunPrimaryAATrigger(trigger, address, JSON.parse(definition));
						}
```

**File:** network.js (L3939-3961)
```javascript
		case 'light/dry_run_aa':
			if (!params)
				return sendErrorResponse(ws, tag, "no params in light/dry_run_aa");
			if (!ValidationUtils.isValidAddress(params.address))
				return sendErrorResponse(ws, tag, "address not valid");
		
			storage.readAADefinition(db, params.address, null, function (arrDefinition) {
				if (!arrDefinition)
					return sendErrorResponse(ws, tag, "not an AA");
				aa_composer.validateAATriggerObject(params.trigger, function(error){
					if (error)
						return sendErrorResponse(ws, tag, error);
					aa_composer.dryRunPrimaryAATrigger(params.trigger, params.address, arrDefinition, function (arrResponses) {
						if (constants.COUNT_WITNESSES === 1) { // the temp unit might have rebuilt the MC
							db.executeInTransaction(function (conn, onDone) {
								storage.resetMemory(conn, onDone);
							});
						}
						if (ws.library_version === '0.4.2' && arrResponses.length === 1 && arrResponses[0].bounced && typeof arrResponses[0].response.error === 'object')
							arrResponses[0].response.error = arrResponses[0].response.error.message;
						sendResponse(ws, tag, arrResponses);
					});
				})
```
