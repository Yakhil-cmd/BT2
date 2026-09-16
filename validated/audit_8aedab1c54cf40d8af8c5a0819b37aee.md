### Title
Use-after-free-style stale cache access in `revertResponsesInCaches` when a stabilized AA response unit is evicted from `assocUnstableUnits` before a later rollback in the same trigger chain - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s `revertResponsesInCaches()` unconditionally dereferences `storage.assocUnstableUnits[first_unit]` to look up `parent_units` for cache repair when an AA trigger chain is rolled back. If that unit object has already been moved out of `assocUnstableUnits` (deleted) by MC stabilization that ran earlier in the very same trigger-processing call stack, the reference is stale/gone, causing a crash on dereferencing `.parent_units` of `undefined` — the JS-land analog of using a freed object.

### Finding Description
`revertResponsesInCaches` is called from `revert()` in `handleTrigger` whenever a step later in the same AA trigger cascade fails and previously-produced (but not-yet-final) AA responses in `arrResponses` must be rolled back: [1](#0-0) 

It grabs the very first response unit and looks up its live in-memory props solely from `storage.assocUnstableUnits[first_unit]`, then unconditionally reads `.parent_units` from it: [2](#0-1) 

Response units for secondary AAs are saved individually via `writer.saveJoint` as soon as each secondary AA finishes, before the primary trigger's remaining messages are processed: [3](#0-2) 

`writer.saveJoint` inserts the newly created unit into `storage.assocUnstableUnits` and can, in the same call, invoke `main_chain.updateMainChain`, which advances the main chain and can call `markMcIndexStable` synchronously in the very same processing chain: [4](#0-3) [5](#0-4) 

`markMcIndexStable` moves any unit whose `main_chain_index` matches the newly stabilized MCI directly out of `assocUnstableUnits` into `assocStableUnits`: [6](#0-5) 

If, after a secondary AA's response unit is saved and immediately stabilized this way, a subsequent message in the *same* primary trigger execution fails (formula error, balance/complexity/state error, etc.), `revert()` is invoked and calls `revertResponsesInCaches(arrResponses)` where `arrResponses` still references the now-stabilized unit. `storage.assocUnstableUnits[first_unit]` is `undefined` at that point, so `objFirstUnit.parent_units` throws a TypeError. This mirrors the reported bug class: an object (`objFirstUnit`) that the caching layer has already "freed" (moved/evicted from the live unstable map) is nonetheless dereferenced by code that still believes it is live, because there is no defensive check (`if (!objFirstUnit) ...`) analogous to a use-after-free guard.

Compare with `forgetUnit`, which is the sibling routine and also assumes `assocUnstableUnits[unit]` is always present without a null check: [7](#0-6) 

### Impact Explanation
This code executes while the process holds the global `"write"` mutex during AA trigger execution (invoked from `stabilizeMci` → `handleAATriggers` → `handleTrigger`, all serialized under the write lock). An uncaught exception here is not defensively handled anywhere in the call chain shown, so it propagates as an uncaught exception in the write-locked critical section. On a live full node this halts unit/joint processing entirely (the write lock is never released), meaning the node can no longer save new units or advance stability — i.e., the node becomes unable to confirm new units until restarted. Because AA execution is deterministic given the same trigger/DAG state, any node that reaches the same code path (any full node executing the same AA cascade, including witnesses) is equally susceptible, so this can propagate into a broad denial of service against AA processing/stabilization across the network, not merely a single actor's local issue.

An attacker who can author or trigger AAs (an unprivileged capability — anyone can post a unit/trigger to an AA address, and anyone can author an AA) can craft an AA chain (a primary AA whose messages call one or more secondary AAs) designed so that:
1. A secondary AA emits a response unit that itself advances the main chain and gets immediately stabilized during `writer.saveJoint`.
2. A later message evaluated back in the primary AA fails (e.g., deliberately triggering a bounce condition, such as insufficient balance/complexity/state-var storage limit) after step 1, forcing `revert()`.

### Likelihood Explanation
Triggering this requires the attacker to control: (a) an AA definition with a payment/message chain that invokes at least one secondary AA before a later message that can be made to fail on demand, and (b) DAG/timestamp conditions such that the secondary AA's response unit lands exactly on the MC and stabilizes synchronously within `writer.saveJoint`'s `updateMainChain` step before the primary trigger's later message is evaluated. This ordering is plausible but timing/DAG-state dependent (it is not guaranteed on every invocation), which lowers likelihood from "trivial" to "conditional but reproducible by a determined attacker who can iterate trigger units and observe stabilization timing," since AA execution and stabilization are otherwise deterministic and repeatable given the same conditions.

### Recommendation
Add a defensive check in `revertResponsesInCaches` (and in `forgetUnit`) before dereferencing cache entries: if `storage.assocUnstableUnits[first_unit]` (or any subsequent unit in `arrResponseUnits`) is missing because it has already been moved to `assocStableUnits`, skip the stale-parent `is_free` fixup for that already-stabilized unit instead of throwing, and avoid calling `forgetUnit`/`fixIsFreeAfterForgettingUnit` on units that are no longer in `assocUnstableUnits`. More robustly, prevent an AA response unit that is part of an in-flight (not-yet-finalized) trigger cascade from being eligible for MC stabilization/eviction until the entire outer trigger has completed (e.g., defer `updateMainChain`/`markMcIndexStable` invocation until after the full primary trigger, including possible rollback, has resolved).

### Proof of Concept
Conceptual reproduction (exact DAG timing to force synchronous stabilization inside `writer.saveJoint` could not be fully confirmed via static reading and would require live-node experimentation, which is out of scope for this static analysis):
1. Deploy Primary AA `P` whose `messages` array contains: (a) a `payment` message that sends funds to Secondary AA `S`, invoking a secondary trigger; (b) a later message (e.g., another `payment` or `state` message) engineered to fail deterministically (e.g., insufficient balance/storage overflow) causing `bounce()`/`revert()` in `handleTrigger`.
2. Deploy Secondary AA `S` with a response message design that yields a response unit likely to fall on/advance the main chain (e.g., built with minimal parents/high witnessed level in a low-throughput test network) so that `writer.saveJoint`'s `updateMainChain` call stabilizes it in the same synchronous chain.
3. Post a trigger unit to `P`. Internally: `S`'s response unit is saved and (if conditions align) stabilized/evicted from `assocUnstableUnits` via `markMcIndexStable` before the primary trigger evaluates the later failing message.
4. The later message fails, invoking `revert()` → `revertResponsesInCaches(arrResponses)`, which does `storage.assocUnstableUnits[S_response_unit].parent_units` on an entry that no longer exists, throwing and crashing unit processing under the write lock. [1](#0-0)

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

**File:** writer.js (L646-653)
```javascript
							arrOps.push(function(cb){
								console.log("updating MC after adding "+objUnit.unit);
								main_chain.updateMainChain(conn, batch, null, objUnit.unit, objValidationState.bAA, (_arrStabilizedMcis, _bStabilizedAATriggers) => {
									arrStabilizedMcis = _arrStabilizedMcis;
									bStabilizedAATriggers = _bStabilizedAATriggers;
									cb();
								});
							});
```

**File:** main_chain.js (L1288-1307)
```javascript
function markMcIndexStable(conn, batch, mci, onDone){
	if (!onDone)
		return new Promise(resolve => markMcIndexStable(conn, batch, mci, resolve));
	profiler.start();
	let count_aa_triggers;
	var arrStabilizedUnits = [];
	if (mci > 0)
		storage.assocStableUnitsByMci[mci] = [];
	for (var unit in storage.assocUnstableUnits){
		var o = storage.assocUnstableUnits[unit];
		if (o.main_chain_index === mci && o.is_stable === 0){
			o.is_stable = 1;
			storage.assocStableUnits[unit] = o;
			storage.assocStableUnitsByMci[mci].push(o);
			arrStabilizedUnits.push(unit);
		}
	}
	arrStabilizedUnits.forEach(function(unit){
		delete storage.assocUnstableUnits[unit];
	});
```

**File:** storage.js (L2209-2232)
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
```
