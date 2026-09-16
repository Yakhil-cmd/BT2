Based on my investigation, I found a concrete analog: an unchecked cache dereference in `aa_composer.js` that mirrors the MongoDB bug's pattern — a field that is normally populated by an earlier phase of a two-phase operation being dereferenced without a null-check in a later, structurally-separate phase (here, "primary trigger" fires immediately after a unit is marked stable, and relies on a cache entry that the stabilization step is responsible for populating).

### Title
Null-dereference DoS in AA primary-trigger guard via unpopulated `assocStableUnits` cache - ([File: aa_composer.js])

### Summary
`handleTrigger()` in `aa_composer.js` checks whether a trigger's originating unit has already produced a primary response by reading `storage.assocStableUnits[trigger.unit].count_aa_responses` without verifying that `storage.assocStableUnits[trigger.unit]` is defined. This mirrors the reported MongoDB bug class: a value that one code path is expected to populate before a later "continuation" step consumes it, but which can be missing in edge-case control flow, causing an unhandled dereference of `undefined`.

### Finding Description [1](#0-0) 

```
if (!bSecondary) {
    if ((trigger.outputs.base || 0) < bounce_fees.base) {
        return bounce('received bytes are not enough to cover bounce fees');
    }
    for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
        if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
            return bounce('received ' + asset + ' is not enough to cover bounce fees');
        }
    }
    // skip this check for dry-run which uses genesis unit as trigger unit
    if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
        return bounce('a second primary trigger from the same unit is not allowed');
}
```

`storage.assocStableUnits[trigger.unit]` is expected to have been populated when the triggering unit became stable, in `main_chain.js`'s `markMcIndexStable()`/stabilization path [2](#0-1)  which inserts `aa_triggers` rows and later runs `handleAATriggers()` in `aa_composer.js` [3](#0-2) . The assumption is that any unit referenced by an `aa_triggers` row is already present in the `assocStableUnits` in-memory cache. However, `writer.js` explicitly calls `storage.resetMemory(conn)` on a failed/rolled-back write [4](#0-3) , and the additional-stabilization loop in `writer.js` repeatedly takes fresh connections, calls `main_chain.advanceMcStability()`, and then invokes `aa_composer.handleAATriggers()` across multiple iterations and multiple independent DB transactions [5](#0-4) . This multi-phase, multi-transaction design (stabilize → cache update → separately trigger AA execution) is structurally the same "two-phase, cache-dependent continuation" pattern as the MongoDB aggregation/getMore bug: phase 1 (stabilization) is supposed to leave a cache entry populated for phase 2 (trigger execution) to consume, but no defensive check exists if that invariant is violated (e.g., by a cache reset from a concurrent failed write, or any code path that races with the assumed ordering). When `storage.assocStableUnits[trigger.unit]` is `undefined` at the time `handleTrigger` runs, `.count_aa_responses` throws an uncaught `TypeError: Cannot read properties of undefined`, which is not caught anywhere in the AA-trigger execution chain and crashes the node process (all `handleTrigger`/`handlePrimaryAATrigger` call sites use plain callbacks with no try/catch around this line).

### Impact Explanation
An uncaught `TypeError` in the core unit-stabilization pipeline (which every full node runs autonomously and synchronously as part of processing new stable units) crashes the node process. Because AA-trigger execution is mandatory and deterministic consensus logic (every full node must execute the same triggers to agree on state/balances), a reliably reproducible crash here is a network-wide denial-of-service vector: any full node reaching this code path with a stale/missing cache entry halts, and if the crafted condition is deterministic across nodes, it can stop the network from processing further units, matching the "network unable to confirm new units" impact bar.

### Likelihood Explanation
The likelihood is **uncertain based on static analysis alone**. I was not able to fully trace every code path that populates `storage.assocStableUnits` at each `markMcIndexStable` step ordering relative to `handleAATriggers`/`handleTrigger` invocations within a single stabilization/COMMIT boundary — this would require deeper live tracing through `storage.js`'s cache-update helpers and the exact happens-before relationship between `writer.js`'s `resetMemory` call (fired only on `err` in that transaction) and the various `aa_composer.handleAATriggers()` calls in the same or a subsequent transaction. It is plausible that in normal operation the cache is always populated in time, and the missing-null-check is defensive-programming debt rather than an actually reachable crash from a single posted unit/trigger. Confirming exploitability requires either instrumented testing (forcing a write failure/rollback mid-stabilization while an AA trigger is pending) or deeper tracing of `storage.js`'s stable-unit cache-population code, which was not fully covered in this investigation due to index/tool limitations.

### Recommendation
Add an explicit guard before dereferencing the cache entry, e.g.:
```js
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && mci >= constants.pemCurvesFixMci) {
    const objTriggerUnitProps = storage.assocStableUnits[trigger.unit];
    if (!objTriggerUnitProps)
        return bounce('trigger unit not found in stable cache'); // or throw a well-defined, caught error
    if (objTriggerUnitProps.count_aa_responses)
        return bounce('a second primary trigger from the same unit is not allowed');
}
```
Additionally, audit all other unchecked `storage.assocStableUnits[...]`/`assocUnstableUnits[...]` accesses inside the AA execution and stabilization paths for the same missing-cache-entry class of bug, and ensure `storage.resetMemory()` cannot be invoked concurrently with, or between transactionally-separated phases of, pending AA-trigger execution.

### Proof of Concept
A definitive PoC requires reproducing the specific timing/ordering where `storage.assocStableUnits[trigger.unit]` is absent when `handleTrigger` evaluates the "second primary trigger" guard — for example, forcing a `saveJoint` failure (triggering `storage.resetMemory`) concurrently with a pending `aa_triggers` row for the same unit, then observing the subsequent `handleAATriggers()` invocation crash with `TypeError: Cannot read properties of undefined (reading 'count_aa_responses')`. I could not construct and verify this timing scenario with the available static-analysis tools; live/dynamic testing (e.g., a Devin session with terminal access to run the ocore test suite and inject a forced write failure) would be needed to confirm reachability from a single posted unit.

### Citations

**File:** aa_composer.js (L91-150)
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
							var batch_start_time = Date.now();
							batch.write({ sync: true }, function(err){
								console.log("AA batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("AA composer: batch write failed: "+err);
								conn.query("COMMIT", function () {
									conn.release();
									if (arrResponses.length > 1) {
										// copy updatedStateVars to all responses
										if (arrResponses[0].updatedStateVars)
											for (var i = 1; i < arrResponses.length; i++)
												arrResponses[i].updatedStateVars = arrResponses[0].updatedStateVars;
										// merge all changes of balances if the same AA was called more than once
										let assocBalances = {};
										for (let { aa_address, balances } of arrResponses)
											assocBalances[aa_address] = balances; // overwrite if repeated
										for (let r of arrResponses) {
											r.balances = assocBalances[r.aa_address];
											r.allBalances = assocBalances;
										}
									}
									else
										arrResponses[0].allBalances = { [address]: arrResponses[0].balances };
									arrResponses.forEach(function (objAAResponse) {
										if (objAAResponse.objResponseUnit)
											arrPostedUnits.push(objAAResponse.objResponseUnit);
										eventBus.emit('aa_response', objAAResponse);
										eventBus.emit('aa_response_to_unit-'+objAAResponse.trigger_unit, objAAResponse);
										eventBus.emit('aa_response_to_address-'+objAAResponse.trigger_address, objAAResponse);
										eventBus.emit('aa_response_from_aa-'+objAAResponse.aa_address, objAAResponse);
									});
									onDone();
								});
							});
						});
					});
				});
			});
		});
	});
}
```

**File:** aa_composer.js (L1851-1863)
```javascript
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
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

**File:** writer.js (L708-713)
```javascript
								if (err) {
									var headers_commission = require("./headers_commission.js");
									headers_commission.resetMaxSpendableMci();
									delete storage.assocUnstableMessages[objUnit.unit];
									await storage.resetMemory(conn);
								}
```

**File:** writer.js (L738-759)
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
```
