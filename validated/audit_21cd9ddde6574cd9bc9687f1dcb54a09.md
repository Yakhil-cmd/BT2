### Title
Uncaught exception in AA trigger processing can permanently stall the `aa_triggers` queue and crash full nodes - ([File: aa_composer.js])

### Summary
`DefaultStateManager.assessStates` in the reference report gets permanently stuck because a downstream call (`ProtectionPool.lockCapital`) can revert due to an external condition (pause), and this revert propagates all the way up through a loop that has no error isolation, leaving the state manager unable to make progress. The analogous condition in ocore is `aa_composer.js`'s `handleAATriggers` / `handlePrimaryAATrigger` pipeline, which processes the `aa_triggers` table as a strict, mutex-protected queue with `async.eachSeries`, and contains `throw Error(...)` statements deep inside nested asynchronous callbacks that are not wrapped in any try/catch or domain. An uncaught throw in this chain is fatal to the Node.js process and, because the offending row is never deleted from the `aa_triggers` queue table before the crash, the stuck trigger is retried and rethrows on every subsequent process restart / call to `handleAATriggers`, exactly mirroring the "can become permanently stuck" pattern in the report.

### Finding Description
`handleAATriggers` takes the `aa_triggers` mutex and iterates the `aa_triggers` table sequentially with `async.eachSeries`, delegating to `handlePrimaryAATrigger` for each row: [1](#0-0) 

`handlePrimaryAATrigger` invokes `handleTrigger`, and only after `handleTrigger`'s `onDone` callback fires does it delete the row from `aa_triggers` (`DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?`). Directly before that delete completes, the code does:

```
let objUnitProps = storage.assocStableUnits[unit];
if (!objUnitProps)
    throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
``` [2](#0-1) 

This `throw` (and the sibling `throw Error("AA composer: batch write failed: "+err)` a few lines later) occurs inside a deeply nested chain of `conn.query(...)` and `batch.write(...)` callbacks — there is no surrounding `try/catch`, and no `domain`/`process.on('uncaughtException')` handler exists in the codebase to intercept it (confirmed by searching the repo; the only `uncaughtException` references are in `network.js` for peer-connection error handling, not around AA processing). In plain Node.js, an exception thrown inside an asynchronous callback like this is uncaught and terminates the process.

`handleTrigger` itself contains many similar unguarded `throw Error(...)` calls reachable from state that depends on unit/AA content, e.g. inside `validateAndSaveUnit`'s `ifJointError`/`ifTransientError`/`ifNeedHashTree`/`ifNeedParentUnits`/`ifOkUnsigned` branches: [3](#0-2) 

and inside `handleSecondaryTriggers` (`throw Error("secondary triggers while bouncing")`) and `finish` (`throw Error('response_unit with bouncing a secondary AA')`): [4](#0-3) [5](#0-4) 

Because `handleAATriggers` re-reads and re-processes *all* rows still present in `aa_triggers` from the top on every invocation, and because the offending row's delete never happens if the process crashes mid-processing, any full node that restarts will re-select the same trigger row (`aa_triggers` is described explicitly as "a queue" in the schema: [6](#0-5) ) and hit the same throw again — an infinite crash loop, i.e. a permanent stall of AA-trigger processing analogous to `DefaultStateManager` looping forever on the same stuck pool.

Since `handleAATriggers()` is invoked deterministically by every full node after every MCI stabilization (from `main_chain.js`'s `markMcIndexStable`/`stabilizeMci` and from `writer.js`'s `saveJoint`), any condition that reliably causes one of these unguarded throws to fire is not a single-node bug — it reproduces on every full node in the network that processes the same trigger, because AA execution is meant to be fully deterministic. [7](#0-6) [8](#0-7) 

### Impact Explanation
If an attacker can construct a payment/AA-trigger unit and AA state such that one of these unguarded `throw` statements executes (for example, exploiting the timing/cache-consistency assumption behind `storage.assocStableUnits[unit]` being populated, or driving `handleTrigger` into one of the "impossible" `ifNeedHashTree`/`ifTransientError`/`ifNeedParentUnits` branches for an internally-generated AA response unit), every full node that stabilizes that MCI will crash while executing `handleAATriggers`. Because the trigger row is never removed from the `aa_triggers` queue before the crash, restarting the node re-triggers the exact same code path and the same crash — a permanent, network-wide denial of service that halts stabilization of further MCIs (since new stable MCIs also enqueue new AA triggers that would never get processed, and full nodes cannot safely diverge in which triggers they execute). This matches the "permanent DoS" impact bar in the report (unable to advance state, network unable to confirm/execute new AA units).

### Likelihood Explanation
Exploitability depends entirely on finding a concrete way to force the codebase into one of the "should never happen" `throw` branches from externally-controlled unit/trigger content — none of the citations above prove that such a state is reachable purely through unprivileged unit posting; they only establish that the code path exists and is unguarded. Without an explicit way to violate the assumptions (e.g., `storage.assocStableUnits[unit]` missing, or an "impossible" validation branch actually being hit) using only externally postable data, the likelihood cannot be assessed as concretely demonstrated — this would require additional analysis of the validation/caching invariants in `storage.js` to confirm reachability by an unprivileged AA-trigger sender.

### Recommendation
- Wrap the AA-trigger processing pipeline (`handleAATriggers` → `handlePrimaryAATrigger` → `handleTrigger`) in defensive error handling so that an unexpected internal inconsistency bounces/skips the single offending trigger (marking it failed/removed from the queue) instead of throwing an uncaught exception that crashes the whole node.
- Ensure the `aa_triggers` row is removed (or marked as permanently failed) in a `finally`-equivalent manner even when unexpected exceptions occur inside `handlePrimaryAATrigger`, so a bad trigger cannot indefinitely block the queue after a restart.
- Audit each `throw Error(...)` reachable from `handleTrigger`/`handleSecondaryTriggers`/`validateAndSaveUnit` to confirm none can be triggered by attacker-controlled unit content, and convert any that can into a `bounce()` response instead of a hard `throw`.

### Proof of Concept
Not conclusively demonstrable from static analysis alone: reaching the throw at `aa_composer.js:105-106` (`storage.assocStableUnits[unit]` being unexpectedly missing) or the "impossible" validation branches inside `validateAndSaveUnit` (`aa_composer.js:1800-1838`) requires driving an internal cache/validation invariant into an inconsistent state using only externally postable units/triggers, which was not proven within the scope of this review. A concrete PoC would require constructing a specific AA definition/trigger sequence (or a race between unit propagation and MCI stabilization) that empirically hits one of these unguarded throws, which needs dynamic testing against the actual node rather than code inspection.

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

**File:** aa_composer.js (L101-115)
```javascript
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
```

**File:** aa_composer.js (L1671-1688)
```javascript
	function finish(objResponseUnit) {
		if (bBouncing && bSecondary) {
			if (objResponseUnit)
				throw Error('response_unit with bouncing a secondary AA');
			if (!bAddedResponse && objValidationState.logs) // add the logs from the final bouncing unit
				arrResponses.push({ logs: objValidationState.logs });

			if (typeof error_message === 'string') {
				error_message = { message: error_message };
			}

			let errorObj = { address };
			if (error_message.address) {
				errorObj.next = error_message;
			} else {
				errorObj = { ...errorObj, ...error_message };
			}
			return onDone(null, errorObj);
```

**File:** aa_composer.js (L1718-1720)
```javascript
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
```

**File:** aa_composer.js (L1800-1838)
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
	}
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
