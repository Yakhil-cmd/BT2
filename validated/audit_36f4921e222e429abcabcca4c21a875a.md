### Title
Single malformed/edge-case AA response unit crashes the whole node instead of bouncing only the offending trigger - (File: aa_composer.js)

### Summary
`handleAATriggers` iterates over all AA triggers due for a stabilized MCI with `async.eachSeries` and processes each `(unit, address)` pair through `handlePrimaryAATrigger` → `handleTrigger` → `validateAndSaveUnit`, one at a time, each in its own DB transaction/batch [1](#0-0) . The framework already has a per-trigger isolation mechanism (`bounce()`/`revert()`) that is supposed to contain *expected* errors (bad formula, insufficient balance, invalid outputs) to the single trigger being processed [2](#0-1) . However, several code paths that validate/save the internally-composed AA response unit bypass this isolation and instead perform a bare, uncaught `throw Error(...)` inside deeply nested async callbacks, which is not routed through `cb`/`onDone` at all [3](#0-2) .

### Finding Description
`validateAndSaveUnit` calls `validation.validate` on the AA-composed response joint and, for outcomes other than the expected `ifOk`, unconditionally throws instead of bouncing just the current trigger: [4](#0-3) 

The same unconditional-throw pattern recurs in `handlePrimaryAATrigger` itself, e.g. when the just-stabilized trigger unit is unexpectedly missing from the props cache, or when the KV batch write fails: [5](#0-4) 

And in `handleSecondaryTriggers`, an unexpected state (`bBouncing` while about to process secondary triggers) also throws rather than isolating the failure to the offending secondary trigger: [6](#0-5) 

These throws execute inside nested `db.query`/`conn.query`/`batch.write` callbacks, not inside a promise chain that any caller awaits with try/catch. `handleAATriggers` (invoked per-stabilized-MCI from `writer.js` after `saveJoint` commits) has no top-level try/catch around the `async.eachSeries` loop, and there is no `process.on('uncaughtException')` handler covering this code path in the codebase — the only `uncaughtException` handlers present are unrelated and scoped to `network.js` [7](#0-6) . Consequently, any edge case that causes the composed AA response unit to fail joint/unit validation unexpectedly (a case the "expected-error" `bounce()` path does not cover, e.g. an edge-case interaction of trigger data/formula output with size limits, chash generation, or the `ifTransientError`/`ifNeedHashTree`/`ifNeedParentUnits`/`ifOkUnsigned` branches) throws synchronously inside the callback stack and crashes the entire node process.

Because `handleAATriggers` processes *all* AA triggers due at a stabilized MCI (potentially many independent AAs/addresses) in one `async.eachSeries` run, a single trigger that hits one of these throw paths halts processing of every other pending trigger in that batch and prevents the node from continuing to process any further units at all until it is manually restarted — the exact "single bad item halts the whole batch, with total silence about which entry caused it beyond a crash log" pattern described in the report, mapped onto AA definitions/triggers and oscript/ojson evaluation instead of Chainlink report decoding.

### Impact Explanation
A full/AA-hosting node that crashes stops confirming and processing new units (and specifically stops running the AA-trigger queue) until manually restarted, i.e. the node becomes unable to process new units — matching the "network unable to confirm new units" impact bucket. Multiple unrelated AAs and their pending triggers are stalled by one AA's edge case, and there is no mechanism to skip/log-and-continue as the code already does for the more common bounce() cases, so operators have very limited diagnostic signal (a crash instead of a bounce log/response). This is a liveness/availability issue for the AA subsystem, reachable purely by posting a unit that triggers an AA (no privileged role required).

### Likelihood Explanation
Reachability requires only posting a unit to any AA address, which is available to any user (AA trigger sender). Triggering the specific throw branches requires hitting an edge case not already covered by the normal bounce mechanism (e.g., `ifTransientError`, `ifNeedHashTree`, `ifNeedParentUnits`, `ifOkUnsigned`, or a cache-consistency assumption violation) — these are lower-probability than a typical formula error, but they are exactly the class of "unexpected/edge-case" condition (analogous to Data-Streams API latency in the original report) that is plausible in production given AA definitions can construct arbitrarily complex output/formula combinations that indirectly affect the size/shape of the composed response unit.

### Recommendation
Wrap the per-trigger processing in `handleAATriggers`'s `async.eachSeries` iterator (and within `handlePrimaryAATrigger`/`handleTrigger`/`validateAndSaveUnit`) so that unexpected internal errors on one trigger are caught, logged with full context (mci/unit/address), and the loop proceeds to the next queued trigger rather than throwing synchronously. Where a genuine unrecoverable invariant violation exists, isolate the crash/restart to just that trigger's processing (e.g., re-queue it and continue with the rest, or fail closed only for that address) instead of allowing a bare `throw` to abort the entire in-flight batch and take down the whole node.

### Proof of Concept
1. Craft an AA definition whose response-unit construction (via `messages`/formula in `state` or payment blocks) is designed to produce a response unit that is syntactically/structurally valid enough to be built by `aa_composer.js` but fails one of the non-`ifOk` outcomes of `validation.validate` in `validateAndSaveUnit` (e.g., by manipulating output/definition sizes near boundary conditions so that `getUnitHash`/joint structure diverges from what `validation.validate` expects).
2. Post a unit from an unprivileged address that triggers this AA along with several *unrelated, healthy* AAs at the same MCI so they all end up queued in `aa_triggers` for the same stabilization event [8](#0-7) .
3. When `handleAATriggers` reaches the crafted trigger in its `async.eachSeries` loop, `validateAndSaveUnit`'s `ifJointError`/`ifTransientError`/etc. branch throws [4](#0-3) .
4. The uncaught exception propagates out of the nested callback chain with no surrounding try/catch, crashing the node process before the remaining triggers in `arrPostedUnits`/the `rows` loop are processed, halting AA-trigger processing for all other queued AAs until the operator manually restarts the node.

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

**File:** aa_composer.js (L104-114)
```javascript
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
```

**File:** aa_composer.js (L1717-1719)
```javascript
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
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

**File:** writer.js (L724-727)
```javascript
								if (bStabilizedAATriggers && !err) {
									console.log(`executing AA triggers`);
									const aa_composer = require("./aa_composer.js");
									await aa_composer.handleAATriggers();
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
