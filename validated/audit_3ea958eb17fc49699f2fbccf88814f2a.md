### Title
Unreleased `handleJoint` / author-address locks on AA dry-run trigger crash cause permanent node-wide validation deadlock - (File: network.js)

### Summary
`ocore` mirrors the PJSIP bug class from ALPINE-CVE-2021-41141 (locks held across an error path that is never released, leading to deadlock/DoS). In `network.js`, the unit-validation success path (`ifOk`) performs an `await`ed AA "dry run" *before* releasing the `handleJoint` mutex and the per-author-address validation lock. If the dry run throws, both locks are left held forever, which stops the node from ever validating another unit.

### Finding Description
`handleJoint()` in `network.js` acquires the process-wide `handleJoint` mutex before calling `validation.validate()`: [1](#0-0) 

`validation.validate()` itself takes a second lock keyed on the unit's author addresses and defers releasing it to the caller by handing over an `unlock` function (named `validation_unlock`) inside the `ifOk` callback, rather than releasing it before invoking the callback: [2](#0-1) 

In `network.js`'s `ifOk` handler, before either `validation_unlock()` (author-address lock) or `unlock()` (`handleJoint` lock) are called, the code performs an `await`ed AA dry run for every AA address targeted by a "primary" AA trigger contained in the newly-received unit: [3](#0-2) 

The comment explicitly states the intent: *"if it would crash, let it crash now, not when we execute the trigger for real"* — i.e., the code deliberately allows `aa_composer.dryRunPrimaryAATrigger()` to throw. Because this call sits inside an `async` callback and is `await`ed with no surrounding `try/catch`, a thrown exception rejects the promise returned by the `ifOk` async function instead of being caught and handled. Execution never reaches the subsequent `writer.saveJoint(...)` call where `validation_unlock()` and `unlock()` are ultimately invoked: [4](#0-3) 

Since `mutex.lock()`'s queueing mechanism only reschedules queued jobs when `unlock()` is explicitly invoked, an un-released `handleJoint` key permanently blocks the queue for that key: [5](#0-4) 

Every unit received afterward — from any peer, wallet, or trigger — funnels through the same `mutex.lock(['handleJoint'], ...)` call at the top of `handleJoint()`, so once the lock is stuck, the node can never validate or save another unit again. This is functionally identical to the PJSIP class of bug: an error/exception path skips the lock-release step, producing a permanent deadlock rather than a clean failure.

### Impact Explanation
Once the `handleJoint` lock is stuck, the affected node stops confirming or accepting any new units (payments, AA triggers, asset transfers, etc.) — a full denial of service for that node's ability to reach consensus/serve its users, matching the "network unable to confirm new units" acceptance criterion. Because a single crafted AA trigger (something any unprivileged unit poster/AA trigger sender can construct) is sufficient to hit the dry-run path, this can be weaponized without any special privileges once the feature is enabled.

### Likelihood Explanation
The vulnerable path is gated behind `conf.bDryRunNewTriggers && !conf.bLight && !objJoint.ball && objValidationState.count_primary_aa_triggers`. This flag is not set in the default `conf.js` that ships with the repository (no default value found), so it is opt-in for full/hub nodes that explicitly enable it. On any node where the flag is enabled, an attacker only needs to craft a unit whose AA trigger data causes the AA formula evaluator to throw during the dry run (e.g., malformed oscript inputs that a full, real execution would otherwise handle gracefully through the AA engine's own error containment, but which crash the ad-hoc dry-run invocation). Because the lock is only ever released after the dry run completes, no repeated attempts or timing race is required — a single successful crash is enough to permanently wedge the node.

### Recommendation
- Wrap the dry-run block in `network.js` (`network.js:1271-1281`) in a `try/catch`, ensuring `validation_unlock()` and `unlock()` are always invoked (or routed through the existing error callbacks) regardless of whether the dry run throws.
- Alternatively, move the dry-run check before the locks are acquired, or make `dryRunPrimaryAATrigger` non-throwing (catch internally and report the crash via a controlled error callback), consistent with how the rest of `handleJoint`'s callbacks convert AA/validation failures into `ifUnitError`/`ifTransientError` responses rather than uncaught exceptions.
- Add a watchdog/timeout on mutex-held keys (`mutex.js`) so any bug that fails to call `unlock()` cannot lock a key forever.

### Proof of Concept
1. Enable `conf.bDryRunNewTriggers = true` (and ensure `conf.bLight` is false) on a target node.
2. Craft and broadcast a payment unit whose output is a primary AA trigger to an AA address, with a trigger payload/data engineered so that AA formula evaluation throws an uncaught exception during the dry run performed in `network.js:1280` (`aa_composer.dryRunPrimaryAATrigger`).
3. The node's `handleJoint` async callback's promise rejects before reaching `validation_unlock()`/`unlock()` in `network.js:1283-1294`.
4. Observe that the `handleJoint` mutex key remains locked (`mutex.js:61-86`); every subsequently submitted unit (from any peer or the node's own wallet) queues indefinitely and is never validated, confirming a persistent denial of service.

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

**File:** network.js (L1258-1294)
```javascript
				ifOk: async function(objValidationState, validation_unlock){
					clearHost();
					if (objJoint.unsigned)
						throw Error("ifOk() unsigned");
					if (bPosted && objValidationState.sequence !== 'good') {
						validation_unlock();
						callbacks.ifUnitError("The transaction would be non-serial (a double spend)");
						delete assocUnitsInWork[unit];
						unlock();
						if (ws)
							writeEvent('nonserial', ws.host);
						return;
					}
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
					}
					writer.saveJoint(objJoint, objValidationState, null, function(){
						validation_unlock();
						callbacks.ifOk();
						unlock();
						if (ws)
							writeEvent((objValidationState.sequence !== 'good') ? 'nonserial' : 'new_good', ws.host);
						notifyWatchers(objJoint, objValidationState.sequence === 'good', ws);
						if (objValidationState.arrUnitsGettingBadSequence)
							notifyWatchersAboutUnitsGettingBadSequence(objValidationState.arrUnitsGettingBadSequence);
						if (!bCatchingUp)
							eventBus.emit('new_joint', objJoint);
					});
```

**File:** validation.js (L474-489)
```javascript
				else{
					profiler.stop('validation-messages');
					profiler.start();
					commit_fn(function(){
						var consumed_time = Date.now()-start_time;
						profiler.add_result('validation', consumed_time);
						console.log(objUnit.unit+" validation ok took "+consumed_time+"ms");
						if (!external_conn)
							conn.release();
						profiler.stop('validation-commit');
						if (objJoint.unsigned){
							unlock();
							callbacks.ifOkUnsigned(objValidationState.sequence === 'good');
						}
						else
							callbacks.ifOk(objValidationState, unlock);
```

**File:** mutex.js (L61-86)
```javascript
function handleQueue(){
	console.log("handleQueue "+arrQueuedJobs.length+" items");
	for (var i=0; i<arrQueuedJobs.length; i++){
		var job = arrQueuedJobs[i];
		if (isAnyOfKeysLocked(job.arrKeys))
			continue;
		arrQueuedJobs.splice(i, 1); // do it before exec as exec can trigger another job added, another lock unlocked, another handleQueue called
		console.log("starting job held by keys", job.arrKeys);
		exec(job.arrKeys, job.proc, job.next_proc);
		i--; // we've just removed one item
	}
	console.log("handleQueue done "+arrQueuedJobs.length+" items");
}

function lock(arrKeys, proc, next_proc){
	if (arguments.length === 1)
		return new Promise(resolve => lock(arrKeys, resolve));
	if (typeof arrKeys === 'string')
		arrKeys = [arrKeys];
	if (isAnyOfKeysLocked(arrKeys)){
		console.log("queuing job held by keys", arrKeys);
		arrQueuedJobs.push({arrKeys: arrKeys, proc: proc, next_proc: next_proc, ts:Date.now()});
	}
	else
		exec(arrKeys, proc, next_proc);
}
```
