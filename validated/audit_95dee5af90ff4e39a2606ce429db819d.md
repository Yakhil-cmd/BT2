## Finding

### Title
Reachable assertion crashes full nodes when an AA response unit validation hits `ifTransientError` (or other unexpected validation outcomes) - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s `validateAndSaveUnit()` function, which validates the AA's own generated response unit while executing a trigger, treats several outcomes of `validation.validate()` as "impossible" and unconditionally `throw`s an `Error` instead of handling them gracefully. In particular `ifTransientError`, `ifJointError`, `ifNeedHashTree`, `ifNeedParentUnits`, and `ifOkUnsigned` all `throw Error(...)`. [1](#0-0) 

Any uncaught exception in ocore is fatal: `network.js` installs a process-wide `uncaughtException` handler that logs and then re-throws to deliberately crash the process ("to avoid ending up in an inconsistent state"). [2](#0-1) 

### Finding Description
`validation.validate()` legitimately calls `ifTransientError` with the message "last ball just advanced, try again" whenever, during validation of a unit, the referenced `last_ball_unit` becomes stable in the middle of the validation flow (a race that is part of normal DAG stability advancement, not an attacker exploit per se): [3](#0-2) 

This code path is reachable for any unit going through `validation.validate`, including AA-generated response units, because `objValidationState.last_ball_mci`/parents handling is common to all units. `aa_composer.js` calls this same `validation.validate` on the AA's freshly composed response unit inside `validateAndSaveUnit`, but unlike `network.js`'s `handleJoint` (which handles `ifTransientError` gracefully by unlocking, removing the unhandled joint, and possibly retrying) [4](#0-3) 
the AA path has no such handling — it just throws, which propagates up through `handleTrigger`/`handleAATriggers` (executed while processing a poster's AA trigger) and reaches the top-level `uncaughtException` handler, crashing the node.

An attacker who is an unprivileged AA trigger sender can influence the timing/shape of AA response-unit composition (e.g., by sending triggers that cause the AA engine to build and validate a response exactly as the DAG's stability point is advancing, or by causing the underlying condition for `ifNeedHashTree`/`ifNeedParentUnits`/`ifJointError` to be hit for the composed unit). Because none of these are "impossible" states from the validator's point of view — they are regular races/conditions handled elsewhere in the codebase (`network.js`) — treating them as fatal assertions in `aa_composer.js` converts a normal validation race into an unconditional crash.

This mirrors the CVE-2024-24429 bug class: a reachable assertion/unhandled fatal condition in a message/state-machine handler for attacker-influenced input (there: NGAP `EMM`→`ESM` state transition; here: AA trigger → response-unit validation state transition) causes the whole process to abort, i.e., a Denial of Service.

### Impact Explanation
If reachable, any full node that executes AA triggers (which happens automatically as part of consensus processing of stable units) can be crashed by a trigger sender orchestrating the timing of AA responses relative to stability advancement, or by any state that trips `ifJointError`/`ifNeedHashTree`/`ifNeedParentUnits`/`ifOkUnsigned` for an internally-composed unit. Because all full nodes run the same deterministic AA engine on the same trigger units, a single crafted trigger can crash every full node that processes it — a network-wide denial of service, matching the "network unable to confirm new units" impact category.

### Likelihood Explanation
The `ifTransientError("last ball just advanced, try again")` condition is a documented, naturally occurring race in `validateParents` tied to MC stability advancement, not a contrived edge case; the difficulty is only in reliably orchestrating trigger timing to force this race to occur while a specific AA is composing its response, which a determined attacker controlling both trigger cadence and DAG structure (units are permissionless to post) can attempt repeatedly until successful. The `ifJointError`, `ifNeedHashTree`, and `ifNeedParentUnits` branches are considered "should never happen" for internally generated units, but the composer builds inputs/outputs and parent references based on transient state that is subject to concurrent modification while unlocking/relocking mutexes across the trigger pipeline (`handleSecondaryTriggers`, `revert`, `bounce`), so the invariant is not obviously airtight either.

### Recommendation
In `aa_composer.js`'s `validateAndSaveUnit`, replace the unconditional `throw Error(...)` in `ifTransientError` (and ideally `ifJointError`/`ifNeedHashTree`/`ifNeedParentUnits`) with the same graceful handling pattern used in `network.js::handleJoint` — i.e., release locks, log the condition, and retry validation of the AA response unit (or defer/re-trigger AA processing) instead of crashing the process. At minimum, wrap the trigger-processing pipeline so a transient/race condition surfaces as a recoverable error rather than an uncaught exception that reaches `process.on('uncaughtException', ...)`.

### Proof of Concept
1. An attacker submits an AA trigger to an AA `X` such that `X`'s response composition (parents, `last_ball_unit`) is computed at a moment where the DAG's stability point for that `last_ball_unit` is about to advance to stable in the current node's view (achievable by controlling unit submission timing/parent selection around the stability boundary, similar to normal `last_ball_just_advanced` occurrences already observed in `network.js`'s handling of regular units).
2. `aa_composer.js` builds the AA response unit and calls `validateAndSaveUnit(objUnit, cb)`, which calls `validation.validate`.
3. `validateParents` detects the stability advance mid-validation and calls `callbacks.ifTransientError(createTransientError("last ball just advanced, try again"))`. [5](#0-4) 
4. `aa_composer.js`'s `ifTransientError` handler throws an uncaught `Error`, which is caught by `process.on('uncaughtException', ...)` in `network.js`, logged, and re-thrown, crashing the full node process. [6](#0-5) [2](#0-1)

### Citations

**File:** aa_composer.js (L1800-1821)
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
```

**File:** network.js (L1203-1218)
```javascript
				ifTransientError: function(error){
				//	throw Error(error);
					console.log("############################## transient error "+error);
					clearHost();
					callbacks.ifTransientError ? callbacks.ifTransientError(error) : callbacks.ifUnitError(error);
					process.nextTick(unlock);
					joint_storage.removeUnhandledJointAndDependencies(unit, function(){
					//	if (objJoint.ball)
					//		db.query("DELETE FROM hash_tree_balls WHERE ball=? AND unit=?", [objJoint.ball, objJoint.unit.unit]);
						delete assocUnitsInWork[unit];
					});
					if (error.includes("last ball just advanced"))
						setTimeout(rerequestLostJoints, 10 * 1000, true);
					if (error === "possible AA" && bCatchingUp)
						tryToAdvanceStabilityPointForCatchupAATrigger(objJoint);
				},
```

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```

**File:** validation.js (L803-817)
```javascript
						main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, last_ball_unit, objUnit.parent_units, objLastBallUnitProps.is_stable, function(bStable, bAdvancedLastStableMci){
							/*if (!bStable && objLastBallUnitProps.is_stable === 1){
								var eventBus = require('./event_bus.js');
								eventBus.emit('nonfatal_error', "last ball is stable, but not stable in parents, unit "+objUnit.unit, new Error());
								return checkNoSameAddressInDifferentParents();
							}
							else */if (!bStable)
								return callback(objUnit.unit+": last ball unit "+last_ball_unit+" is not stable in view of your parents "+objUnit.parent_units);
							if (bAdvancedLastStableMci)
								return callback(createTransientError("last ball just advanced, try again"));
							if (!bAdvancedLastStableMci)
								return checkNoSameAddressInDifferentParents();
							conn.query("SELECT ball FROM balls WHERE unit=?", [last_ball_unit], function(ball_rows){
								if (ball_rows.length === 0)
									throw Error("last ball unit "+last_ball_unit+" just became stable but ball not found");
```
