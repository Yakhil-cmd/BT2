## Title
Unhandled internal AA-unit validation/write errors cause a full node crash instead of a graceful bounce - (File: `aa_composer.js`)

### Summary
`aa_composer.js`'s `validateAndSaveUnit()` — the function every full node calls to validate and persist a deterministically-computed AA response unit — treats several `validation.validate()` outcomes (`ifJointError`, `ifTransientError`, `ifNeedHashTree`, `ifNeedParentUnits`, `ifOkUnsigned`) and any error from `writer.saveJoint()` as unrecoverable conditions and `throw`s a bare `Error`, rather than returning the error to the caller (`bounce()`/`revert()`), which is the pattern used for the ordinary `ifUnitError` case just above it. [1](#0-0) 

### Finding Description
`handleTrigger()` composes an AA response unit deterministically from trigger data, AA state, and the AA definition, then calls `validateAndSaveUnit(objUnit, cb)` to validate and write it: [2](#0-1) 

Inside `validateAndSaveUnit`, only `ifUnitError` is handled softly (logged and passed back via `cb(err)`, which flows into `bounce(err)`); every other branch throws synchronously: [1](#0-0) 

Because AA execution is fully deterministic and run independently by every full node that processes the same primary/secondary trigger unit at the same MCI, any condition that pushes the composed response into one of the `throw`-guarded branches (e.g., `writer.saveJoint` returning an error such as a duplicate-unit/DB constraint failure on reprocessing, or the composed unit unexpectedly tripping `ifTransientError`/`ifJointError` in `validation.js`) will crash *every* full node executing that AA in lock-step, not just a single malicious peer's connection. This is architecturally different from ordinary joint-validation error handling elsewhere in the codebase (e.g. `network.js` `handleJoint`), where `ifJointError`/`ifTransientError` are deliberately *not* thrown and are instead routed to graceful peer-error responses: [3](#0-2) 

The uncaught exception subsequently propagates to the global handler, which intentionally kills the process: [4](#0-3) 

This mirrors the class of bug described in the Lotus report: an error path that should be surfaced and handled (a config/initialization error in Lotus; an AA validation/write error here) is instead turned into a hard panic/crash.

### Impact Explanation
Because AA triggers are posted by unprivileged users/AAs and AA execution is deterministic across all full nodes, hitting one of these `throw` branches does not just take down one node's connection to one peer — it can simultaneously crash every full node in the network that processes the same trigger (at the same point in the deterministic AA state machine). This maps to "a network unable to confirm new units": nodes restart, lag, or refuse to advance past the offending trigger/MCI, causing a consensus-availability disruption reachable purely by posting an ordinary AA trigger.

### Likelihood Explanation
Likelihood depends on finding a concrete deterministic input (trigger data / AA definition) that pushes the composed response unit into the `ifJointError`/`ifTransientError`/`writer.saveJoint`-error branches instead of the handled `ifUnitError` or `ifOk` branches — for example a duplicate re-processing scenario after a main-chain reorg causing `writer.saveJoint` to fail on an already-inserted unit. The code paths leading there are non-trivial edge cases (reorg-driven re-validation, secondary-trigger races), so likelihood is moderate rather than trivially exploitable, but the throw-on-error design means any occurrence — even a rare race — is catastrophic rather than degrading gracefully.

### Recommendation
Replace the `throw Error(...)` calls in `validateAndSaveUnit` (for `ifJointError`, `ifTransientError`, `ifNeedHashTree`, `ifNeedParentUnits`, `ifOkUnsigned`, and the `writer.saveJoint` error callback) with calls into the existing `bounce()`/`revert()` error-handling flow used for `ifUnitError`, so that unexpected AA-unit validation/write failures produce a bounced AA response (or a safely logged/retried state) instead of an unrecoverable process crash. Add regression coverage that forces each of these branches (e.g. by mocking `writer.saveJoint` to return an error) to confirm the node continues operating.

### Proof of Concept
Not applicable in the strict PoC sense — this is a structural code-review finding based on control-flow analysis of `aa_composer.js:1800-1838` versus the graceful-error-handling pattern established in `network.js:1174-1218`, following the same "unhandled internal error causes panic instead of a controlled error return" pattern flagged in the referenced Lotus commit.

### Citations

**File:** aa_composer.js (L1405-1424)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
									if (arrOutputAddresses.length === 0)
										return finish(objUnit);
									fixStateVars();
									addResponse(objUnit, function () {
										updateStorageSize(function (err) {
											if (err)
												return revert(err);
											handleSecondaryTriggers(objUnit, arrOutputAddresses);
										});
									});
								});
							});
						});
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

**File:** network.js (L1174-1218)
```javascript
			validation.validate(objJoint, {
				ifUnitError: function(error){
					console.log(objJoint.unit.unit+" validation failed: "+error);
					clearHost();
					callbacks.ifUnitError(error);
					if (constants.bDevnet)
						throw Error(error);
					purgeJointAndDependenciesAndNotifyPeers(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
					unlock();
					if (ws && error !== 'authentifier verification failed' && !error.match(/bad merkle proof at path/) && !bPosted)
						writeEvent('invalid', ws.host);
					if (objJoint.unsigned)
						eventBus.emit("validated-"+unit, false);
				},
				ifJointError: function(error){
					clearHost();
					callbacks.ifJointError(error);
				//	throw Error(error);
					joint_storage.saveKnownBadJoint(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
					unlock();
					if (ws)
						writeEvent('invalid', ws.host);
					if (objJoint.unsigned)
						eventBus.emit("validated-"+unit, false);
				},
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
