### Title
Race condition: dry-run AA trigger execution mutates shared DAG caches without holding the write lock - ([File: network.js])

### Summary
The Linux `vsock` bug (CVE-2025-21756) was a use-after-free caused by removing/modifying a shared, reference-counted binding outside of the synchronization that was supposed to protect it during a state transition. The analogous root cause in `ocore` is that `aa_composer.dryRunPrimaryAATrigger()`, invoked directly from unit-reception code for an *unconfirmed, unsaved* unit, mutates the same global in-memory DAG bookkeeping structures (`storage.assocUnstableUnits`, `storage.assocBestChildren`, `storage.assocUnstableMessages`) that `writer.saveJoint()` uses for real unit commits, but does so **without acquiring the `"write"` mutex** that serializes all other access to these structures.

### Finding Description
When a full node receives a new unit whose output pays an AA address, and `conf.bDryRunNewTriggers` is enabled, `network.js` runs the AA trigger "for real" (dry run) before the unit is even validated/saved, purely to catch crashes early: [1](#0-0) 

This happens inside `handleJoint()`'s `ifOk` callback, which is protected only by the `mutex.lock(['handleJoint'])` acquired earlier in `validate()`, not by the `"write"` lock: [2](#0-1) 

`dryRunPrimaryAATrigger()` opens its own DB connection/transaction and calls `handleTrigger()`, which for every generated AA response unit calls `validateAndSaveUnit()` → `writer.saveJoint()`, but explicitly marks the call as already holding the write lock: [3](#0-2) 

`writer.saveJoint()` trusts this flag and skips acquiring the `"write"` mutex entirely: [4](#0-3) 

Yet inside that "unlocked" `saveJoint()` call, the code still inserts the phantom (dry-run) unit into the *same shared, process-global* caches that every other unit save (which *does* take the `"write"` lock) also mutates: [5](#0-4) 

After the dry run finishes, `aa_composer.js`'s `revert()`/`revertResponsesInCaches()` "undoes" these mutations purely at the JavaScript level (SQL `ROLLBACK` cannot undo them, since they are plain object/array mutations, not DB rows): [6](#0-5) [7](#0-6) 

Because none of this — insertion, best-child linkage, `is_free` recomputation, or removal — is guarded by the `"write"` lock, a concurrent legitimate unit save that *is* holding `"write"` (the normal path for any other incoming unit) can observe the DAG in a transient, dry-run-polluted state: a parent's `assocBestChildren` list can temporarily contain a unit that will never really exist, or `fixIsFreeAfterForgettingUnit()` can flip a parent's `is_free` flag based on the phantom unit's presence/absence right as another writer is deciding which units are free tips to consume as parents. This is structurally the same bug class as the vsock CVE: an object's membership in a shared tracking structure is added/removed outside the lock/refcount discipline that the rest of the system assumes protects it during a lifecycle transition, letting another concurrent actor observe or act on stale/incorrect membership.

### Impact Explanation
Corruption of `assocUnstableUnits` / `assocBestChildren` / `is_free` state is exactly the in-memory state main-chain selection, level/witnessed-level computation, and free-tip selection depend on (`main_chain.updateMainChain`, `writer.js` parent consumption). If two nodes hit this race at different times (inherently non-deterministic, since it depends on transaction/interleaving timing local to each node), they can compute divergent main-chain/stability decisions for the same set of units, producing node disagreement on unit validity/stability — one of the accepted high-impact outcomes for this scan. In the worst case, a phantom "best child" or an incorrectly toggled `is_free` flag could let a genuine unit be built on a parent state the rest of the network doesn't share, risking stalled stabilization or divergent DAG views.

### Likelihood Explanation
The trigger condition — a full (non-light) node with `conf.bDryRunNewTriggers` enabled receiving any unit whose outputs are addressed to an existing AA — is reachable by any unprivileged unit poster; no special peer/hub trust is required, matching the "AA trigger sender" reachable-path requirement. The race window (dry-run transaction lifetime vs. a concurrently arriving, unrelated unit's `"write"`-locked save) is narrow but is a genuine TOCTOU condition inherent to the code path, not something requiring attacker-controlled timing precision beyond flooding the node with units.

### Recommendation
Do not let `dryRunPrimaryAATrigger()` (or any other caller that sets `bUnderWriteLock=true` without actually holding `"write"`) mutate the shared caches `storage.assocUnstableUnits`, `storage.assocBestChildren`, and `storage.assocUnstableMessages` outside of the `"write"` mutex. Either:
- Acquire `mutex.lock(["write"])` around the entire dry-run trigger execution in `network.js` before calling `aa_composer.dryRunPrimaryAATrigger`, or
- Make the dry-run path operate on a private, non-shared snapshot/clone of these caches (as the estimate/`estimatePrimaryAATrigger` path already partly does via `stateVars`/`assocBalances` parameters) instead of mutating the process-wide `storage.*` maps directly.

### Proof of Concept
1. Run a full node with `conf.bDryRunNewTriggers = true`.
2. Have an existing AA address `A` with a parent unit `P` that is a "free" (unconsumed) tip.
3. Attacker submits/broadcasts unit `U1` paying `A`, timed so that its dry-run trigger execution (which references and mutates `assocBestChildren[P]`/`is_free` via the phantom response unit) is in-flight.
4. Concurrently, submit unit `U2` from another connection that legitimately consumes `P` as a parent via the normal `writer.saveJoint()` (protected by `"write"`).
5. Depending on interleaving, `U2`'s view of `P`'s free/best-child state can be corrupted by `U1`'s not-yet-reverted (or already-reverted, but overlapping) dry-run mutations, since neither path is mutually excluded by the same lock.

### Citations

**File:** network.js (L1165-1174)
```javascript
	var validate = function(){
		mutex.lock(['handleJoint'], function(unlock){
			if (ws && !conf.bLight)
				currentJointHost = ws.host;
			// clear host only if validation completed with any result, otherwise it crashed and we keep it for a while to avoid DoS from the same peer
			const clearHost = () => {
				if (ws && !conf.bLight)
					currentJointHost = null;
			};
			validation.validate(objJoint, {
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

**File:** aa_composer.js (L1819-1836)
```javascript
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

**File:** writer.js (L24-35)
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
```

**File:** writer.js (L590-613)
```javascript
			var batch = bCordova ? null : (bInLargerTx ? objValidationState.batch : kvstore.batch());
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

**File:** storage.js (L2209-2248)
```javascript
function forgetUnit(unit){
	console.log('forgetting unit '+unit);
	if (!conf.bLight){
		console.log('parents', assocUnstableUnits[unit].parent_units);
		assocUnstableUnits[unit].parent_units.forEach(function(parent_unit){
			console.log('parent '+parent_unit+' best children', JSON.stringify(assocBestChildren[parent_unit]));
			if (assocBestChildren[parent_unit] && assocBestChildren[parent_unit].indexOf(assocUnstableUnits[unit]) >= 0){
				console.log('before pull', assocBestChildren[parent_unit]);
				_.pull(assocBestChildren[parent_unit], assocUnstableUnits[unit]);
				console.log('after pull', assocBestChildren[parent_unit]);
			}
		});
	}
	delete assocKnownUnits[unit];
	delete assocCachedUnits[unit];
	delete assocCachedUnitAuthors[unit];
	delete assocCachedUnitWitnesses[unit];
	delete assocUnstableUnits[unit];
	if (!conf.bLight && assocStableUnits[unit])
		throw Error("trying to forget stable unit "+unit);
	delete assocStableUnits[unit];
	delete assocUnstableMessages[unit];
	delete assocBestChildren[unit];
}

// parent_units are parent units of the forgotten unit
function fixIsFreeAfterForgettingUnit(parent_units) {
	parent_units.forEach(function(parent_unit){
		if (!assocUnstableUnits[parent_unit]) // the parent is already stable
			return;
		var bHasChildren = false;
		for (var unit in assocUnstableUnits){
			var o = assocUnstableUnits[unit];
			if (o.parent_units.indexOf(parent_unit) >= 0)
				bHasChildren = true;
		}
		if (!bHasChildren)
			assocUnstableUnits[parent_unit].is_free = 1;
	});
}
```
