### Title
Unprivileged AA trigger can crash full nodes via unhandled `throw Error` in `validateAndSaveUnit` - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `validateAndSaveUnit()` treats every non-`ifOk`-with-`sequence==='good'` result from `validation.validate()` on an internally generated AA response unit as an unrecoverable, unexpected condition and responds by throwing a bare `Error`, which is never caught anywhere in the call chain (`handleTrigger` → `sendUnit` → `validateAndSaveUnit`). Any uncaught exception reaches Node's top-level `uncaughtException` handler in `network.js`, which explicitly re-throws to crash the process. Because AA trigger execution is deterministic and driven entirely by attacker-supplied trigger data (a normal, unprivileged unit sent to an AA address), a trigger crafted to make the AA-generated response fail one of these checks (joint error, transient error, non-serial sequence, unexpected need for hash tree/parents, or writer error) will crash every full node that processes it — a network-wide denial of service, analogous to the CVE-2019-2819 MySQL audit-subsystem crash/DoS caused by unexpected/attacker-influenced internal state.

### Finding Description
`validateAndSaveUnit()` composes a `objJoint` for the AA's own response unit and calls `validation.validate()`: [1](#0-0) 

Every branch other than the happy path (`ifOk` with `sequence === 'good'`) throws:
- `ifJointError` → `throw Error("AA validation joint error: " + err)`
- `ifTransientError` → `throw Error("AA validation transient error: " + err)`
- `ifNeedHashTree` → `throw Error(...)`
- `ifNeedParentUnits` → `throw Error(...)`
- `ifOkUnsigned` → `throw Error(...)`
- `ifOk` with non-good sequence → `throw Error("nonserial AA")`
- writer error → `throw Error('AA writer returned error: ' + err)`

This code is invoked from `handleTrigger`'s `sendUnit()` after evaluating the AA's oscript/ojson definition against attacker-controlled `trigger` data (address, outputs, `data` payload) that any unprivileged unit poster can send to a public AA address: [2](#0-1) 

The core `validate()` function itself contains numerous code paths that legitimately return `ifJointError`/`ifTransientError` (e.g., wrong headers/payload commission, wrong payload hash, bad `tps_fee`/`oversize_fee`, "last ball just advanced", version/mci mismatches) or set `sequence` to non-`good`, all of which are ordinary, non-fatal conditions when validating units received from peers, but are treated as fatal, crash-worthy bugs when they occur on the AA's *own* generated unit: [3](#0-2) [4](#0-3) 

Any uncaught exception anywhere in the process is caught by the global handler in `network.js`, which deliberately re-throws to kill the node: [5](#0-4) 

Because AA execution is part of the deterministic consensus/state-advance mechanism, this is not merely a single connection failing — it is executed synchronously as part of MC-stability processing on every full node, so the crash propagates network-wide as each node independently reaches the same MCI and re-executes the same trigger.

### Impact Explanation
A successful trigger causes every full node (and the hub) that advances past the MCI containing the malicious trigger to hit the same code path and crash with an uncaught exception, per the explicit `uncaughtException` handler that re-throws to terminate the process. This matches the "network unable to confirm new units" and node-disagreement/availability class of impact called for in the validation rules — nodes must be manually restarted, and if any state/fee-calculation edge case in the composer diverges even slightly from what `validate()` expects (e.g., an oversize-fee/tps-fee rounding discrepancy triggered by a specific combination of AA outputs, asset messages, or `temp_data`), a single crafted trigger can be replayed against every node in the network, resulting in a sustained denial of confirmation service.

### Likelihood Explanation
Triggering an AA is available to any unprivileged unit poster and requires no special privilege — sending a payment (or data) message to a published AA address is a standard, permissionless operation. The likelihood of actually finding an input that produces a joint-error/transient-error/non-serial condition on the *self-generated* unit depends on discovering an edge case in the AA composer's fee/size/sequence computation that diverges from `validate()`'s expectations (e.g. interactions among `oversize_fee`, `tps_fee`, `temp_data`, asset messages, or double-spend sequencing across secondary triggers within the same or overlapping MCIs). Given the size and complexity of `validate()` (commission size checks, tps/oversize fee upgrades, `max_aa_responses`, temp-data length/hash checks, sequence/non-serial determination), and that these code paths are already known to be delicate (guarded by version/mci feature flags such as `pemCurvesFixMci`, `v4UpgradeMci`), an edge case reachable purely through trigger content is plausible, making this a realistic (not purely theoretical) DoS vector.

### Recommendation
Do not `throw` on `ifJointError`, `ifTransientError`, `ifNeedHashTree`, `ifNeedParentUnits`, `ifOkUnsigned`, or non-good `sequence` in `validateAndSaveUnit()`. Instead, treat these as bounce-able trigger failures (call the existing `bounce()`/`cb(err)` path used for `ifUnitError`) so that a malformed or unexpected AA-generated unit fails the trigger gracefully rather than crashing the node. At minimum, wrap this validation call and its surrounding logic so any thrown error is caught and converted into a bounce, preventing propagation to the global `uncaughtException` handler.

### Proof of Concept
Conceptual PoC (requires a live network / full test harness to fully realize, so described procedurally):
1. Publish an AA whose response-generation logic, combined with the AA composer's fee/size accounting (`sendUnit`/`completePaymentPayload` in `aa_composer.js`), produces a response unit whose `payload_commission`/`oversize_fee`/`tps_fee` fields disagree with what `validate()` independently recomputes (or that causes `sequence` to resolve to non-`good` due to a crafted double-spend across chained/secondary triggers).
2. As an ordinary unprivileged user, send a trigger unit to this AA's address with the constructed `data`/`outputs` that hit the divergent computation.
3. When full nodes process the trigger and call `aa_composer.handleTrigger` → `sendUnit` → `validateAndSaveUnit`, `validation.validate()` returns `ifJointError`/`ifTransientError`/non-good `sequence` on the AA's own unit.
4. `validateAndSaveUnit` throws an uncaught `Error`, which reaches `network.js`'s `process.on('uncaughtException', ...)` handler, which re-throws and crashes the node process, per [5](#0-4) .

### Citations

**File:** aa_composer.js (L1382-1411)
```javascript
				pickParents(function (parent_units) {
					objUnit.parent_units = parent_units;
					objUnit.headers_commission = objectLength.getHeadersSize(objUnit);
					objUnit.payload_commission = objectLength.getTotalPayloadSize(objUnit);
					var size = objUnit.headers_commission + objUnit.payload_commission;
					console.log('unit before completing bytes payment', util.inspect(objUnit, { depth: 6 }));
					completePaymentPayload(objBasePaymentMessage.payload, size, function (err) {
					//	console.log('--- completePaymentPayload', err);
						if (err)
							return bounce(err);
						addOutputAddresses(objBasePaymentMessage.payload.outputs);
						try {
							completeMessage(objBasePaymentMessage); // fixes payload_hash
						}
						catch (e) {
							return bounce("base completeMessage failed: " + e.toString());
						}
						objUnit.payload_commission = objectLength.getTotalPayloadSize(objUnit);
						const oversize_fee = (mci >= constants.v4UpgradeMci) ? storage.getOversizeFee(objUnit, last_ball_mci, true) : 0;
						if (oversize_fee)
							objUnit.oversize_fee = oversize_fee;
						objUnit.unit = objectHash.getUnitHash(objUnit);
						console.log('unit', util.inspect(objUnit, { depth: 6 }))
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
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

**File:** validation.js (L742-746)
```javascript
					if (!objValidationState.bAA && !bHaveNonAAParent && objValidationState.last_ball_mci >= constants.v4UpgradeMci)
						return callback("non-AA unit should have at least one non-AA parent");
					if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && objValidationState.bAA && objValidationState.last_ball_mci < constants.pemCurvesFixMci)
						return callback("unit too large");
					
```

**File:** validation.js (L1258-1268)
```javascript
	//	var cross = (objValidationState.max_known_mci - objValidationState.max_parent_limci < 1000) ? 'CROSS' : '';
		var indexMySQL = conf.storage == "mysql" ? "USE INDEX(unitAuthorsIndexByAddressMci)" : "";
		conn.query( // _left_ join forces use of indexes in units
		/*	"SELECT unit, is_stable \n\
			FROM units \n\
			"+cross+" JOIN unit_authors USING(unit) \n\
			WHERE address=? AND (main_chain_index>? OR main_chain_index IS NULL) AND unit != ?",
			[objAuthor.address, objValidationState.max_parent_limci, objUnit.unit],*/
			// final-bad units are permanently voided and never come back to 'good', so they are not real competitors:
			// exclude them here rather than only when deciding bConflictsWithStableUnits below
			"SELECT unit, is_stable, sequence, level \n\
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
