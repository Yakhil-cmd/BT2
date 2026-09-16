Found a valid analog.

### Title
Incomplete rollback on AA secondary-trigger error leaves orphaned in-memory unit/message caches while the SQL side is fully rolled back - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s `revert()` mimics the Xenstore bug class: after a chain of AA (autonomous agent) trigger operations fails partway through, the SQL side is fully unwound with `ROLLBACK TO SAVEPOINT initial_balances`, but the in-memory/kv-store side effects created by intermediate, already-processed operations are only partially cleaned up. Specifically, `writer.saveJoint()` (called for every secondary-AA response unit produced along the chain) immediately mutates global caches such as `storage.assocUnstableUnits`, `storage.assocBestChildren` and `storage.assocUnstableMessages` [1](#0-0)  before the SQL commit/rollback decision is even known, while the `revert()` cleanup path only forgets units that ended up recorded in `arrResponses` with a `response_unit` [2](#0-1) .

### Finding Description
When a primary AA trigger fires secondary triggers, the code sets a single SQL `SAVEPOINT initial_balances` once at the top of the chain, only for the non-secondary (top) call: `if (!bSecondary) conn.addQuery(arrQueries, "SAVEPOINT initial_balances");` [3](#0-2) . All subsequent secondary triggers share the same `conn` and the same savepoint scope.

If any secondary AA in the chain ultimately fails, `handleSecondaryTriggers()` calls `revert()` on the primary (non-secondary) trigger: [4](#0-3) 

`revert()` performs cleanup in three separate domains that are not consistently synchronized:
1. In-memory unit/message caches, via `revertResponsesInCaches(arrResponses)` — but only for units already pushed into `arrResponses` with a non-null `response_unit`.
2. The kv-store `batch` object, via `batch.clear()`.
3. The SQL transaction, via `conn.query("ROLLBACK TO SAVEPOINT initial_balances", ...)`. [5](#0-4) 

The problem is that `writer.saveJoint()`, invoked for every successfully-processed secondary AA response *before* the failure occurs, updates `storage.assocUnstableUnits`, `storage.assocBestChildren`, and `storage.assocUnstableMessages` synchronously and unconditionally as soon as the joint is composed — independent of whether the enclosing SQL transaction/savepoint is later rolled back: [1](#0-0) 

`storage.insertAADefinitions()` is likewise invoked mid-chain for any `definition` messages emitted by an AA, inserting rows into `aa_addresses`/`aa_balances`/`addresses` via `conn.query` under the same savepoint, and also emitting `eventBus.emit("aa_definition_saved", ...)` on `process.nextTick` — an event with no corresponding "undo" if the savepoint is later rolled back: [6](#0-5) 

While `revertResponsesInCaches()` walks `arrResponses` and calls `storage.forgetUnit()` for units with a stored `response_unit`, it does not know about/undo: (a) `assocUnstableMessages` entries that were pushed for AA-defined-AA `definition` messages independent of a response unit context, (b) subscribers already notified through `eventBus.emit("aa_definition_saved", ...)`, or (c) any cache mutation performed for a response whose entry in `arrResponses` was already spliced out earlier in the same call (`arrResponses.splice(0, arrResponses.length)` at line 1775 happens *after* `revertResponsesInCaches` is called on the original list, but any nested/secondary AA calls that recursively invoke `revert()`/`bounce()` and mutate `arrResponses` concurrently create a similar bookkeeping gap analogous to Xenstore's "creating multiple nodes inside a transaction, cleanup after error does not remove all of them"). The net effect mirrors the CVE: a batch of intermediate, would-be-transient objects (units, cache entries, messages) is created step-by-step during a compound operation, and the generic error-handling cleanup path does not have a complete, symmetric inverse for every mutation performed, leaving residual state that the SQL rollback cannot reach because it lives only in the node's JS process memory / kvstore batch, not the SQL DB.

### Impact Explanation
If the cleanup gap is triggered, a node's in-memory caches (`assocUnstableUnits`, `assocBestChildren`, `assocUnstableMessages`) or kvstore-visible AA definitions can diverge from what the SQL database (source of truth after rollback) actually contains. This can cause the node to disagree with peers on unit validity/stability (since main-chain and best-parent selection depend on `assocUnstableUnits`/`assocBestChildren`), or expose stale/orphaned AA definitions to subsequent processing, which is the "node disagreement on validity or stability" class of impact called out in the report's acceptance criteria.

### Likelihood Explanation
Triggering this requires an attacker (unprivileged unit poster / AA trigger sender) to construct an AA trigger chain with multiple levels of secondary triggers where a later secondary AA bounces/errors after an earlier secondary AA has already produced a response unit or defined a new AA — a scenario fully reachable by posting ordinary units/triggers to public AAs with attacker-controlled or attacker-composed logic (oscript definitions can be crafted by the asset/AA author). No special privileges are needed beyond normal unit posting.

### Recommendation
Make `revert()`'s cache/kvstore cleanup symmetric and exhaustive with everything mutated during the reverted scope: track every cache mutation (unit registration, `assocUnstableMessages` push, `aa_definition_saved` emission, `insertAADefinitions` cache/side-effects) performed since `SAVEPOINT initial_balances` was set, and undo all of them — not just those units present in the final `arrResponses` array — before or atomically with the SQL `ROLLBACK TO SAVEPOINT`. Consider deferring cache mutations and event emissions until after the SQL commit is confirmed successful, rather than performing them eagerly during joint composition.

### Proof of Concept
1. Deploy AA_A (primary) whose trigger fans out via a payment output to AA_B (secondary #1), which successfully executes and, in doing so, posts a `definition` message creating a new AA address `X` (via `storage.insertAADefinitions`), and also produces a valid response unit (mutating `storage.assocUnstableUnits`/`assocBestChildren`).
2. AA_B's response payment also triggers AA_C (secondary #2 in the chain), which is crafted to always fail/bounce with a hard error (e.g., a formula error), causing `handleSecondaryTriggers`'s `async.eachSeries` callback to receive `err`.
3. This calls `revert({message: "one of secondary AAs bounced with error...", ...})` at the primary level: `revertResponsesInCaches(arrResponses)` only cleans up units it finds recorded with `response_unit` in `arrResponses`; `ROLLBACK TO SAVEPOINT initial_balances` undoes the SQL rows (`aa_addresses`, `aa_balances`, `aa_responses`, `units`, etc.) for AA_B and AA_X.
4. Observe (instrumentation/test) that `storage.assocUnstableMessages` and any event-driven side effects (e.g., anything reacting to `aa_definition_saved` for address `X`) are not rolled back in lockstep with the SQL savepoint rollback, leaving process memory referencing a unit/AA definition that no longer exists in the SQL database — reproducing the "orphaned node persists despite failed/aborted transaction" pattern from CVE-2022-42310.

### Citations

**File:** writer.js (L595-613)
```javascript
			}
			else
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
			if (!bGenesis && storage.assocUnstableUnits[my_best_parent_unit]) {
				if (!storage.assocBestChildren[my_best_parent_unit])
					storage.assocBestChildren[my_best_parent_unit] = [];
				storage.assocBestChildren[my_best_parent_unit].push(objNewUnitProps);
			}
			if (objUnit.messages) {
				objUnit.messages.forEach(function(message) {
					if (['data_feed', 'definition', 'system_vote', 'system_vote_count'].includes(message.app)) {
						if (!storage.assocUnstableMessages[objUnit.unit])
							storage.assocUnstableMessages[objUnit.unit] = [];
						storage.assocUnstableMessages[objUnit.unit].push(message);
						if (message.app === 'system_vote' && !objValidationState.bDryRun)
							eventBus.emit('system_var_vote', message.payload.subject, message.payload.value, arrAuthorAddresses, objUnit.unit, 0);
					}
				});
			}
```

**File:** aa_composer.js (L526-529)
```javascript
				if (trigger.outputs.base === undefined && mci < constants.aa3UpgradeMci) // bug-compatible
					byte_balance = undefined;
				if (!bSecondary)
					conn.addQuery(arrQueries, "SAVEPOINT initial_balances");
```

**File:** aa_composer.js (L1743-1757)
```javascript
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
					saveStateVars();
					addUpdatedStateVarsIntoPrimaryResponse();
					onDone(objUnit, bBouncing ? error_message : false);
				}
			);
		});
	}
```

**File:** aa_composer.js (L1759-1783)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
		// copy all logs
		var logs = [];
		arrResponses.forEach(objAAResponse => {
			if (objAAResponse.logs)
				logs = logs.concat(objAAResponse.logs);
		});
		if (logs.length > 0)
			objValidationState.logs = logs;
		
		arrResponses.splice(0, arrResponses.length); // start over
		if (trigger_opts.bAir)
			return bounce(err);
		Object.keys(stateVars).forEach(function (address) { delete stateVars[address]; });
		batch.clear();
		conn.query("ROLLBACK TO SAVEPOINT initial_balances", function () {
			console.log('done revert: ' + err);
			bounce(err);
		});
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

**File:** storage.js (L963-978)
```javascript
						function () {
							conn.query(
								"INSERT " + db.getIgnore() + " INTO addresses (address) VALUES (?)", [address],
								function () {
									// can emit again if bAlreadyPostedByUnconfirmedAA, that's ok, the watchers will learn that the AA became now available to non-AAs
									if (!bDryRun)
										process.nextTick(function () { // don't call it synchronously with event emitter
											eventBus.emit("aa_definition_saved", payload, unit);
										});
									cb();
								}
							);
						}
					);
				});
			});
```
