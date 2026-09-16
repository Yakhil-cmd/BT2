### Title
Unhandled crash / cache-DB desynchronization when an AA response unit advances main-chain stability inside a savepoint-rollback path - ([File: writer.js], [File: aa_composer.js])

### Summary
`writer.saveJoint()` contains a defensive check that throws an uncaught `Error` if a unit being saved advances main-chain stability while the write is happening "under write lock" / inside a larger transaction (`bInLargerTx || objValidationState.bUnderWriteLock`). AA response units are always saved with `objValidationState.bUnderWriteLock = true` and `bInLargerTx = true` (they share the AA trigger's connection/batch/savepoint). If an attacker can arrange for an AA's response unit to itself become the unit that advances the stability point, every full node executing the deterministic AA trigger hits this `throw`, which fires from inside an `async` callback with no surrounding catch - this is functionally analogous to the NTP use-after-free bug class in that a crafted, protocol-level input (a trigger unit) drives the node into an inconsistent internal state / uncontrolled fault that crashes the process, rather than being handled as a validation error.

### Finding Description
`aa_composer.js`'s `validateAndSaveUnit()` sets `objAAValidationState.bUnderWriteLock = true` and reuses the same `conn`/`batch` as the outer AA-trigger transaction: [1](#0-0) 

`writer.saveJoint()` treats this as `bInLargerTx` (because `objValidationState.conn && objValidationState.batch`) and skips its own write lock: [2](#0-1) 

It immediately mutates the in-memory caches (`storage.assocUnstableUnits`, `storage.assocBestChildren`, `assocUnstableMessages`) before the DB transaction is guaranteed to commit: [3](#0-2) 

Then, after running `main_chain.updateMainChain()` (which can synchronously discover that this same unit stabilizes the main chain and return `arrStabilizedMcis`), the code explicitly guards against this situation - but only by throwing, not by rejecting/aborting the AA trigger gracefully: [4](#0-3) 

This `throw` happens inside an `async function` passed to `commit_fn(...)` (an asynchronous callback), so it becomes an unhandled promise rejection rather than a normal error path that could be caught by `validation.validate`'s or `aa_composer.js`'s error callbacks: [5](#0-4) 

Separately, and even if that specific `throw` is avoided, the AA-trigger rollback path (`revert()` in `aa_composer.js`) only undoes the *unstable-unit* cache entries it created (`revertResponsesInCaches` → `storage.forgetUnit`), and rolls the DB back with `ROLLBACK TO SAVEPOINT initial_balances`. It does not attempt to undo any main-chain-stabilization side effects (`assocStableUnitsByMci`, `assocStableUnits`, `min_retrievable_mci`, TPS-fee state) that `main_chain.updateMainChain()` could have already applied to memory before the savepoint rollback: [6](#0-5) [7](#0-6) 

Both problems stem from the same root cause: AA response units are saved through the same code path (`writer.saveJoint`) used for regular network units, which unconditionally applies certain global side effects (stability advancement, cache mutation) as soon as it runs, but the AA-composer call site assumes it can cheaply and completely roll back via a SQL savepoint plus a partial, hand-rolled cache-revert function. Any code path where an AA response unit can drive stabilization forward breaks this assumption, either crashing the node (defensive `throw`) or silently desynchronizing memory caches from the database if the safety throw were ever removed/bypassed.

### Impact Explanation
Because AA trigger execution is fully deterministic across the network, any single crafted trigger unit that reaches this defensive `throw` will crash *every* full node that executes the trigger at the same MCI, at the same point in processing. That is a network-wide denial of service preventing new units from being confirmed - one of the accepted high-impact outcomes for this class of bug (a network unable to confirm new units due to a crash triggered by a single posted unit/trigger, matching the "crash via crafted packets" bug class of the CVE).

### Likelihood Explanation
The trigger condition (`arrStabilizedMcis.length > 0` while `bUnderWriteLock` is set) requires an AA response unit itself to be the unit that pushes the last-ball/main-chain stability point forward. This is a narrow but not obviously impossible condition to engineer: an attacker/AA author fully controls the AA definition, its outputs, and can arrange trigger timing/witness graph so that the AA's own response unit becomes the best/next main-chain unit. Because ocore's AA feature is reachable by any unprivileged user (posting a trigger to any existing AA, or defining and triggering their own AA), no privileged access is required. Precisely engineering the main-chain graph so the response unit is the stabilizing unit requires some care, so likelihood is assessed as medium rather than trivial, but it is squarely within the "unit poster / AA trigger sender" threat model called out in the rules.

### Recommendation
- Do not `throw` unhandled inside the async `commit_fn` callback in `writer.js`; instead propagate the condition as a normal error to `onDone(err)` so callers (including `aa_composer.js`) can gracefully bounce/reject the trigger instead of crashing the process.
- Make `main_chain.updateMainChain()` refuse to advance `arrStabilizedMcis` at all when `objValidationState.bUnderWriteLock` is true, so an AA response unit can never itself become the stabilizing event; defer that stabilization to be discovered/applied normally on a subsequent, separate write.
- Audit `revertResponsesInCaches`/`forgetUnit` to ensure any cache mutation performed by `main_chain.updateMainChain()` (best-parent/level/witnessed-level/stability caches) is fully reversible, or refuse to enter such a state in the first place, so a savepoint rollback of the SQL transaction can never leave in-memory caches inconsistent with the database.

### Proof of Concept
Not independently executable from static analysis alone: reproducing the crash requires constructing a full round of witnesses/parent units such that an AA's own response unit becomes the next main-chain unit and simultaneously advances the last-ball stability point at the moment `aa_composer.js`'s `handleTrigger` → `validateAndSaveUnit` → `writer.saveJoint` executes it under `bUnderWriteLock`. I was not able to fully verify from the indexed code whether `main_chain.updateMainChain()` can realistically return a non-empty `arrStabilizedMcis` for a unit saved via this specific AA-composer call path (this needs to be validated against `main_chain.js`'s stabilization logic and tested with an actual multi-witness devnet), or whether some upstream guard elsewhere prevents AA response units from ever being main-chain/best-parent candidates. I recommend a Devin session with full repository and test-network access to confirm reachability empirically (e.g., by extending the existing `test/aa_composer.test.js`/`test/aa.test.js` scaffolding, which already exercises `handleTrigger` directly with mock `objMcUnit`/`storage.assocStableUnits`, to force a stabilizing scenario) before treating this as confirmed-exploitable rather than a design weakness.

### Citations

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

**File:** aa_composer.js (L1822-1837)
```javascript
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

**File:** writer.js (L24-41)
```javascript
async function saveJoint(objJoint, objValidationState, preCommitCallback, onDone) {
	var objUnit = objJoint.unit;
	console.log("\nsaving unit "+objUnit.unit);
	var arrQueries = [];
	var commit_fn;
	if (objValidationState.conn && !objValidationState.batch)
		throw Error("conn but not batch");
	var bInLargerTx = (objValidationState.conn && objValidationState.batch);
	const bCommonOpList = objValidationState.last_ball_mci >= constants.v4UpgradeMci;

	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);

	function initConnection(handleConnection) {
		if (bInLargerTx) {
			profiler.start();
			commit_fn = function (sql, cb) { cb(); };
			return handleConnection(objValidationState.conn);
```

**File:** writer.js (L591-613)
```javascript
			if (bGenesis){
				storage.assocStableUnits[objUnit.unit] = objNewUnitProps;
				storage.assocStableUnitsByMci[0] = [objNewUnitProps];
				console.log('storage.assocStableUnitsByMci', storage.assocStableUnitsByMci)
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

**File:** writer.js (L699-707)
```javascript
						saveToKvStore(function(){
							profiler.stop('write-batch-write');
							profiler.start();
							commit_fn(err ? "ROLLBACK" : "COMMIT", async function(){
								var consumed_time = Date.now()-start_time;
								profiler.add_result('write', consumed_time);
								console.log((err ? (err+", therefore rolled back unit ") : "committed unit ")+objUnit.unit+", write took "+consumed_time+"ms");
								profiler.stop('write-sql-commit');
								profiler.increment();
```

**File:** writer.js (L716-723)
```javascript
								if (!err && !objValidationState.bDryRun){
									eventBus.emit('saved_unit-'+objUnit.unit, objJoint);
									eventBus.emit('saved_unit', objJoint);
								}
								if (arrStabilizedMcis.length > 0 && (bInLargerTx || objValidationState.bUnderWriteLock))
									throw Error(`saveJoint stabilized an MCI while in larger tx or under write lock`);
								if (arrStabilizedMcis.length > 1)
									throw Error(`saveJoint stabilized more than one MCI: ${arrStabilizedMcis.join(', ')}`);
```

**File:** storage.js (L1900-1916)
```javascript
		handleAsset = bAcceptUnconfirmedAA;
		bAcceptUnconfirmedAA = false;
	}
	if (last_ball_mci === null){
		if (conf.bLight)
			last_ball_mci = MAX_INT32;
		else
			return readLastStableMcIndex(conn, function(last_stable_mci){
				readAsset(conn, asset, last_stable_mci, bAcceptUnconfirmedAA, handleAsset);
			});
	}
	readAssetInfo(conn, asset, function (objAsset) {
		if (!objAsset)
			return handleAsset("asset " + asset + " not found");
		if (objAsset.sequence !== "good")
			return handleAsset("asset definition is not serial");
		
```
