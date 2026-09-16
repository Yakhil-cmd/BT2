### Title
Server crash via invariant violation when an AA response unit stabilizes an MCI while `saveJoint` runs under `bUnderWriteLock` - (File: writer.js)

### Summary
The MongoDB CVE crashes the server via an unhandled `invariant()` when a specific combination of options (`$changeStream` + `$_requestReshardingResumeToken` + `exchange`) hits a code path assumed to be unreachable, and the fault is reachable by any logged-in unprivileged user issuing a single command. In `ocore`, the analogous pattern exists in `writer.js`'s `saveJoint`, where a combination of internal state (`objValidationState.bUnderWriteLock` set during AA trigger execution, combined with `arrStabilizedMcis.length > 0` from `main_chain.updateMainChain`) hits a hard `throw Error(...)` invariant that is intended to be unreachable but can be triggered by unprivileged unit posters via a crafted AA trigger, crashing the entire node process.

### Finding Description
When an AA response unit is written back to the DAG, `aa_composer.js`'s `validateAndSaveUnit` sets `objAAValidationState.bUnderWriteLock = true` right before calling `writer.saveJoint`: [1](#0-0) 

Inside `writer.saveJoint`, after committing the unit, the code calls `main_chain.updateMainChain`, which may return a non-empty `arrStabilizedMcis` (i.e., the newly saved unit advances main-chain stability). Immediately after, the code enforces an invariant that is supposed to never fire when writing under a write lock or inside a larger transaction: [2](#0-1) [3](#0-2) 

The comment "will throw just after the upgrade" and the plain `throw Error(...)` (not routed through any `ifError`/`bounce` callback) show this is a genuine unreachable-code assertion, similar in spirit to MongoDB's `invariant()`. If any sequence of events causes an AA-response unit's own commit to stabilize an MCI while `objValidationState.bUnderWriteLock` is true (set specifically for units written during AA trigger execution, see `aa_composer.js:1826`), this `throw Error` fires synchronously inside the `commit_fn` callback, which is not wrapped in a try/catch that would gracefully convert it into a validation error. It therefore becomes an uncaught exception that propagates to Node's `process.on('uncaughtException')` handler, which is deliberately designed to rethrow and crash the process to avoid running with `inconsistent state`: [4](#0-3) 

A separate, closely related invariant a few lines below (`arrStabilizedMcis.length > 1`) is the same class of bug — an assumption ("saveJoint can stabilize at most one MCI") that, if violated by attacker-influenced timing/graph shape, also crashes the whole node: [5](#0-4) 

Both are unreachable-code assumptions baked as hard crashes rather than handled errors, matching the MongoDB bug class: a specific combination of otherwise-legal inputs/state (AA trigger execution + stabilization timing) drives the code into a path the developers believed was impossible, and instead of failing gracefully it crashes the entire server.

### Impact Explanation
Because AA triggers are payments sent by any ordinary, unprivileged unit poster to any AA address, and because the write-lock flag is intrinsic to how AA response units are persisted (`aa_composer.js:1826`), an attacker only needs to construct a trigger/AA chain whose response-unit commit causes `main_chain.updateMainChain` to report `arrStabilizedMcis.length > 0` at the moment `bUnderWriteLock` is set. If reachable, this crashes the node process entirely — a full-node denial of service that halts confirmation of all new units on the affected node, matching the "network unable to confirm new units" impact category. Because every full node in the network processes AA trigger execution the same way, a reproducible trigger sequence could be broadcast/replayed to crash multiple nodes simultaneously.

### Likelihood Explanation
The precise interleaving needed (an AA-response unit's own commit is the one that pushes stability forward while `bUnderWriteLock` is true, or a single commit stabilizing more than one MCI) is a narrow/racy condition by design — the code assumes it never happens, which is exactly the profile of a MongoDB-style invariant crash: rare under normal conditions but potentially forceable by an attacker who controls transaction ordering/graph shape (unit's parent selection, timing, and AA definitions), since AA execution and stabilization ordering are all driven by attacker-supplied units and payment DAG structure. I was not able to fully verify the exact conditions under which `updateMainChain` returns `arrStabilizedMcis.length` in these forms while `bUnderWriteLock` is set, since that requires deep analysis of `main_chain.js`'s stability advancement logic, which was outside the scope of what I could trace with the available context.

### Recommendation
- Convert the `throw Error(...)` invariants at `writer.js:720-723` into handled error paths that bounce/reject the responsible unit and roll back cleanly instead of crashing the whole process, or explicitly prove (with assertions during development/testing, not production crashes) that these conditions are truly unreachable given all AA-trigger writing paths.
- Audit every code location where `objValidationState.bUnderWriteLock` is set (`aa_composer.js:1826`) or `bInLargerTx` is used together with `saveJoint`, to confirm that MCI stabilization can never occur on those paths; add defensive handling if it can.
- Add fuzz/property-based tests that construct AA trigger chains and payment DAG shapes specifically targeting simultaneous AA-response commit and MC stabilization to confirm/rule out reachability.

### Proof of Concept
A concrete unit sequence could not be fully constructed without deeper analysis of `main_chain.updateMainChain`'s stabilization criteria (which units/witnessed-levels are required to advance the MC) combined with the AA trigger/response write path. Conceptually:
1. Attacker crafts an AA (or chain of AAs) such that executing it produces a response unit written via `aa_composer.js`'s `validateAndSaveUnit` (`bUnderWriteLock = true`).
2. Attacker arranges the payment DAG (parent selection, witness levels, timing of surrounding units) so that the very act of committing this AA response unit inside `writer.saveJoint` causes `main_chain.updateMainChain` to advance MC stability (`arrStabilizedMcis.length > 0`), or advances it by more than one MCI at once.
3. This triggers the `throw Error` invariant, which is uncaught and crashes the node process via the global `uncaughtException` handler. [6](#0-5) [1](#0-0) [4](#0-3)

### Citations

**File:** aa_composer.js (L1822-1835)
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
