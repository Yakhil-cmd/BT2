I have enough evidence to establish a valid analog. The client-facing "dry run" / estimate APIs are explicitly documented and used to predict AA outcomes, and they diverge from real execution — this is the same class of risk as the Mangrove report (unaware caller relies on a pre-check that isn't a reliable guarantee of the real on-chain outcome).

### Title
Unprotected AA Trigger Senders Can Be Misled by Inaccurate/Stale Dry-Run & Estimate Results, Leading to Unexpected Fund Loss - ([File: aa_composer.js])

### Summary
Obyte's Autonomous Agents (AAs) let any unprivileged party post a trigger unit carrying a payment plus optional data, and the AA's response (bounce/success, payout amounts, recipients) is computed at execution time based on the live blockchain state (balances, other units, timestamps, state vars). To help callers predict what will happen, `ocore` exposes `dryRunPrimaryAATrigger` (used by light clients via the `light/dry_run_aa` network command) and `estimatePrimaryAATrigger` (used to preview effects before a trigger becomes stable). Both are explicitly documented as best-effort approximations, not guarantees.

### Finding Description
`estimatePrimaryAATrigger` carries the comment: "estimates the effects of an AA trigger before it gets stable... The estimation is not 100% accurate, e.g. storage_size is ignored, unit validation errors are not caught". [1](#0-0) 

`dryRunPrimaryAATrigger` is exposed to light-wallet clients through the `light/dry_run_aa` request, letting an unprivileged trigger sender simulate an AA call against fake outputs before broadcasting a real trigger unit. [2](#0-1) 

Both simulation paths run `handleTrigger` with `bAir`/`bDryRun` flags against a synthetic MC unit (genesis unit as fake trigger, or the last stable MC unit with rewritten timestamp/MCI) and fake inserted outputs, then roll back. [3](#0-2) [4](#0-3) 

This is structurally the same design gap flagged in the Mangrove report: a caller (there, a keeper; here, any address posting an AA trigger, e.g. an arbitrage bot, an unaware wallet user, or an integrator relying on `light/dry_run_aa`) must trust an off-chain/pre-execution simulation of outcome, while the actual on-chain execution can diverge because:
1. Real balances, other pending/competing triggers, and state variables can change between the simulation and the moment the real trigger unit is sequenced and executed (`handleAATriggers`/`handlePrimaryAATrigger` use whatever state is current at MCI-stabilization time). [5](#0-4) 
2. The simulation deliberately skips checks that the real path enforces (storage size accounting, full unit validation errors), so a trigger that "looks fine" in `dry_run_aa`/estimate can still fail differently, or a trigger that looks like it will bounce in a way could actually succeed for a different amount, once genuinely executed via `validateAndSaveUnit`. [6](#0-5) 
3. Nothing in the protocol or `ocore` compels callers to re-verify the *actual* response before considering funds committed — the trigger's payment outputs are irrevocably sent as soon as the unit is posted and stabilizes; there is no reverting-wrapper equivalent shipped for the general trigger-sending flow, mirroring Mangrove's "keepers should wrap their calls" risk-accepted stance.

### Impact Explanation
An unprivileged trigger sender (a "keeper"-analog interacting with AAs, e.g. an arbitrage/liquidation bot or automated integrator that pre-checks outcomes via `light/dry_run_aa` or `estimatePrimaryAATrigger`) can commit real funds in a trigger's `outputs` based on a simulated outcome that does not match the actual on-chain result once the trigger becomes stable and is processed by `handlePrimaryAATrigger`. This can lead to sending more value into the AA than intended, receiving a worse payout than predicted, or having the AA bounce/behave differently than the simulation suggested — a direct AA-interaction fund-loss scenario for the trigger sender, analogous to the honeypot-offer risk in the original report.

### Likelihood Explanation
Any address can post an AA trigger unit; there is no privilege requirement. AAs commonly implement logic that depends on current balances, `timestamp`, other addresses' state, or the order/interleaving of concurrent triggers, so estimate/dry-run staleness is a realistic, frequent occurrence rather than a contrived edge case, especially for actively-traded AAs (e.g., DEX/lending-style AAs) where competing triggers race for the same state.

### Recommendation
Since this mirrors an accepted design trade-off (documented explicitly in code comments), the primary mitigation is documentation and client-side protocol design rather than a code fix in `ocore` itself:
- Clearly document in the `light/dry_run_aa` API and `estimatePrimaryAATrigger`/`dryRunPrimaryAATrigger` JSDoc that results are approximate, can miss validation errors/storage-size effects, and can become stale between simulation and execution.
- Encourage/standardize a "revert-if-unexpected-outcome" trigger pattern (e.g., an on-chain guard AA or `bounce()`-based invariant check embedded in the trigger's own consuming logic) so automated callers can enforce their expected minimum outcome atomically, rather than relying purely on off-chain pre-checks.
- Consider surfacing a best-effort "staleness window" or last-known MCI in the `dry_run_aa` response so clients can detect if chain state advanced meaningfully between simulation and broadcast.

### Proof of Concept
1. A bot calls `light/dry_run_aa` for AA `X` with trigger outputs `{base: N}`, observing (via `dryRunPrimaryAATrigger`) a predicted successful response paying out `M` tokens to the bot. [2](#0-1) 
2. Before the bot's real trigger unit is posted and stabilizes, another party posts a competing trigger to the same AA `X`, changing its state vars/balances (e.g. draining a pool, changing a price/rate variable).
3. The bot's real trigger unit is then processed by `handlePrimaryAATrigger`/`handleAATriggers` against the new (different) live state, producing a different real outcome (smaller payout, unexpected bounce, or unexpected recipient amounts) than what the dry run predicted. [5](#0-4) 
4. Because dry run/estimate ignore storage-size effects and some unit validation errors, an outcome that appeared safe in simulation can also fail for reasons never surfaced during the pre-check. [1](#0-0)

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

**File:** aa_composer.js (L152-154)
```javascript
// estimates the effects of an AA trigger before it gets stable.
// stateVars and assocBalances are updated after the function returns.
// The estimation is not 100% accurate, e.g. storage_size is ignored, unit validation errors are not caught
```

**File:** aa_composer.js (L272-306)
```javascript
function dryRunPrimaryAATrigger(trigger, address, arrDefinition, onDone) {
	if (!onDone)
		return new Promise(resolve => dryRunPrimaryAATrigger(trigger, address, arrDefinition, resolve));
	console.log('dry run', address, trigger);
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = conf.bLight ? lightBatch : kvstore.batch();
			readLastStableMcUnit(conn, function (mci, objMcUnit) {
				trigger.unit = constants.GENESIS_UNIT; // objMcUnit.unit; // might cause duplicate trigger_unit in aa_triggers if objMcUnit is already a real trigger
				if (!trigger.address)
					trigger.address = objMcUnit.authors[0].address;
				trigger.initial_address = trigger.address;
				trigger.initial_unit = trigger.unit;
				var fPrepare = function (cb) {
					insertFakeOutputsIntoMcUnit(conn, objMcUnit, trigger.outputs, address, cb);
				};
				fPrepare(function () {
					var arrResponses = [];
					handleTrigger({
						bDryRun: true, // suppress events for a unit that will be rolled back
						conn, batch, trigger, params: {}, stateVars: {}, arrDefinition, address, mci, objMcUnit, bSecondary: false, arrResponses,
						onDone: function () {
							revertResponsesInCaches(arrResponses);
							batch.clear();
							conn.query("ROLLBACK", function () {
								conn.release();
								onDone(arrResponses);
							});
						},
					});
				});
			});
		});
	});
}
```

**File:** aa_composer.js (L323-335)
```javascript
function insertFakeOutputsIntoMcUnit(conn, objMcUnit, outputs, address, onDone) {
	// this ensures we have the funds on AA address in case the response unit tries to send the received funds somewhere else
	console.log('inserting fake outputs into unit ' + objMcUnit.unit);
	var arrQueries = [];
	var message_index = objMcUnit.messages.length;
	for (var asset in outputs) {
		conn.addQuery(arrQueries,
			"INSERT INTO outputs (unit, message_index, output_index, asset, address, amount) VALUES(?, ?,0, ?, ?, ?)",
			[objMcUnit.unit, message_index, asset === 'base' ? null : asset, address, outputs[asset]]);
		message_index++;
	}
	async.series(arrQueries, onDone);
}
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

**File:** network.js (L3939-3961)
```javascript
		case 'light/dry_run_aa':
			if (!params)
				return sendErrorResponse(ws, tag, "no params in light/dry_run_aa");
			if (!ValidationUtils.isValidAddress(params.address))
				return sendErrorResponse(ws, tag, "address not valid");
		
			storage.readAADefinition(db, params.address, null, function (arrDefinition) {
				if (!arrDefinition)
					return sendErrorResponse(ws, tag, "not an AA");
				aa_composer.validateAATriggerObject(params.trigger, function(error){
					if (error)
						return sendErrorResponse(ws, tag, error);
					aa_composer.dryRunPrimaryAATrigger(params.trigger, params.address, arrDefinition, function (arrResponses) {
						if (constants.COUNT_WITNESSES === 1) { // the temp unit might have rebuilt the MC
							db.executeInTransaction(function (conn, onDone) {
								storage.resetMemory(conn, onDone);
							});
						}
						if (ws.library_version === '0.4.2' && arrResponses.length === 1 && arrResponses[0].bounced && typeof arrResponses[0].response.error === 'object')
							arrResponses[0].response.error = arrResponses[0].response.error.message;
						sendResponse(ws, tag, arrResponses);
					});
				})
```
