### Title
Uncaught exception in AA response validation crashes the node - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `handleTrigger()` deterministically builds a response unit whenever an unprivileged user sends a trigger unit to an Autonomous Agent, and then calls `validateAndSaveUnit()` to re-validate that generated unit through the normal `validation.validate()` pipeline before saving it. Every "should never happen" outcome of that re-validation is handled with a synchronous `throw Error(...)` instead of a graceful bounce, mirroring the DNSdist bug class where a crafted request pushes execution down an unexpected/unhandled code path that hits an assertion-style failure and terminates the process. [1](#0-0) 

### Finding Description
When an AA is triggered, `handleTrigger()` composes a response unit and hands it to `validateAndSaveUnit()`, which calls `validation.validate()` with callbacks. Every callback other than the "good" `ifOk` path is a hard `throw Error(...)`:
- `ifJointError` → `throw Error("AA validation joint error: " + err)`
- `ifTransientError` → `throw Error("AA validation transient error: " + err)`
- `ifNeedHashTree` → `throw Error("AA validation unexpected need hash tree")`
- `ifNeedParentUnits` → `throw Error("AA validation unexpected dependencies: ...")`
- `ifOkUnsigned` → `throw Error("AA validation returned ok unsigned")`
- `ifOk` with `sequence !== 'good'` → `throw Error("nonserial AA")` [2](#0-1) 

There is also a similar hard invariant inside secondary-trigger handling: if the AA is in a bouncing state but secondary triggers are still found, the code throws `"secondary triggers while bouncing"` rather than handling it gracefully. [3](#0-2) 

These throws occur deep inside the stabilization/write pipeline (`writer.saveJoint` → `main_chain.advanceMcStability`/`markMcIndexStable` → `aa_composer.handleAATriggers` → `handlePrimaryAATrigger` → `handleTrigger` → `validateAndSaveUnit`), which is executed by every full node as part of normal consensus processing once a trigger unit becomes stable — not only by the node that originally received the trigger. [4](#0-3) [5](#0-4) 

Because these are synchronous throws inside asynchronous callback chains, they are not caught by any local `try/catch`; they propagate up to the process-level `uncaughtException` handler, which explicitly re-throws to crash the process ("crash the process to avoid ending up in an inconsistent state"). [6](#0-5) 

This is the same bug class as CVE-2024-25581: input from an unprivileged actor (here, an AA trigger sender, or the AA author's own oscript logic combined with attacker-supplied trigger data/state) drives execution into a code path whose only handling is an assertion-like `throw`, causing the entire process to terminate — a network-wide, remotely triggerable denial of service rather than a local error.

### Impact Explanation
If an AA trigger sender (any regular user posting a payment+data unit to an AA address) can steer AA execution into one of these "impossible" branches — e.g., causing the generated response unit to conflict with a concurrently confirmed unit and be marked non-serial, or causing dependency/joint errors during re-validation of the deterministically built response — every full node that executes the AA trigger during stabilization will crash with an uncaught exception. Because AA trigger execution is part of consensus-critical stabilization (`markMcIndexStable` → `handleAATriggers`), a reproducible trigger would crash all synced full nodes that process it, halting the network's ability to confirm new units — one of the explicitly in-scope high-impact outcomes.

### Likelihood Explanation
Reaching most of these branches (`ifNeedParentUnits`, `ifNeedHashTree`, `ifTransientError`, `ifOkUnsigned`) requires the deterministically-constructed AA response unit to disagree with the validator's expectations, which is hard to trigger without a concrete state/timing condition. The most plausible avenue is the `"nonserial AA"` branch: since the AA response's inputs/parents are chosen by `pickParents()`/coin selection logic based on current AA balances and unstable-unit state, a specifically timed sequence of triggers/spends (all reachable via plain trigger units to the AA, an action available to any unprivileged user) could cause the freshly composed response unit to fail the standard double-spend/serial-sequence check that `validation.validate()` performs, hitting the `throw Error("nonserial AA")` path. Because it depends on a specific double-spend/race condition rather than a single trivially-crafted request, likelihood is assessed as medium, but severity of the outcome (network-wide crash of full nodes) is high.

### Recommendation
Replace the `throw Error(...)` calls in `aa_composer.js`'s `validateAndSaveUnit()` (and the `"secondary triggers while bouncing"` invariant) with graceful bounce/error handling consistent with the rest of `handleTrigger()`'s error-recovery mechanism (`bounce()`/`revert()`), or at minimum catch these conditions before they reach `validation.validate()` so a single crafted or racily-timed trigger cannot bring down full nodes during consensus stabilization.

### Proof of Concept
1. Deploy or use an existing AA.
2. As an unprivileged sender, submit a trigger unit to the AA while racing another unit that spends the same AA-controlled output the response unit would need to reference as an input (e.g., via a nearly-simultaneous rival payment/trigger designed to get confirmed on a competing branch).
3. When the trigger's MCI stabilizes, `handleAATriggers()` runs `handleTrigger()`, which builds the response unit and calls `validateAndSaveUnit()`.
4. If the response unit's chosen inputs/parents end up conflicting with the raced spend, `validation.validate()`'s `ifOk` callback reports `sequence !== 'good'`, triggering `throw Error("nonserial AA")` inside `aa_composer.js:1824`, which propagates to `process.on('uncaughtException')` in `network.js:4530-4543` and crashes the node. [7](#0-6)

### Citations

**File:** aa_composer.js (L1717-1719)
```javascript
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
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

**File:** main_chain.js (L1263-1276)
```javascript
async function stabilizeMci(mci) {
	const conn = await db.takeConnectionFromPool();
	await conn.query("BEGIN");
	const batch = kvstore.batch();
	const count_aa_triggers = await markMcIndexStable(conn, batch, mci);
	await util.promisify(batch.write.bind(batch))({ sync: true });
	await conn.query("COMMIT");
	conn.release();
	if (count_aa_triggers > 0) {
		console.log(`executing ${count_aa_triggers} AA triggers after stabilizing MCI ${mci}`);
		// every trigger takes its own db connection
		const aa_composer = require("./aa_composer.js");
		await aa_composer.handleAATriggers();
	}
```

**File:** writer.js (L724-727)
```javascript
								if (bStabilizedAATriggers && !err) {
									console.log(`executing AA triggers`);
									const aa_composer = require("./aa_composer.js");
									await aa_composer.handleAATriggers();
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
