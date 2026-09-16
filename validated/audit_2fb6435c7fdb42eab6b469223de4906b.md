### Title
Unauthenticated `light/dry_run_aa` network command executes full AA/oscript trigger logic against arbitrary AAs using attacker-forged trigger data and injects fabricated outputs into the live database - (File: network.js, aa_composer.js)

### Summary
The `light/dry_run_aa` websocket command in `network.js` lets any inbound, unauthenticated peer make a full node execute the complete AA (autonomous agent) trigger-processing pipeline (`handleTrigger`/`evaluateAA`, i.e. oscript evaluation — the closest analog to OFBiz's "screen rendering code") against **any** AA address on the network, with attacker-controlled `trigger` data. Just like the OFBiz bug, the entry point performs only shallow, generic parameter validation and relies on the assumption that deeper protections exist elsewhere, when in fact the reached code path executes privileged business logic (oscript AA formulas) that is normally only ever run for units that have passed full unit/authentifier/DAG validation.

### Finding Description
`network.js` dispatches `light/dry_run_aa` after only checking that the address is syntactically valid and that a basic trigger shape passes `aa_composer.validateAATriggerObject`: [1](#0-0) 

`validateAATriggerObject` only checks object shape, address validity, size limits and that output amounts are positive integers — it performs **no** checks that the caller is entitled to spend/receive at `trigger.address`, no signature, no proof that any real unit or funds exist: [2](#0-1) 

The command then calls `dryRunPrimaryAATrigger`, which takes a real connection from the pool, begins a transaction, and calls `insertFakeOutputsIntoMcUnit`, which performs a genuine `INSERT INTO outputs` against the actual last stable main-chain unit, crediting the attacker-specified `address` with the attacker-specified `outputs` amounts: [3](#0-2) [4](#0-3) 

It then runs the full `handleTrigger` oscript-evaluation pipeline against the live database connection and live in-memory caches (`storage.assocStableUnits`, balances, state vars, etc.), including cascading secondary AA triggers to any other AA the response happens to pay: [5](#0-4) 

The design intends this to be safe because the transaction is rolled back and the batch is cleared at the end: [3](#0-2) 

However, the huge amount of code executed between `BEGIN` and `ROLLBACK` — the entire `handleTrigger` state machine, `evaluateAA`, formula evaluation (`formula/evaluation.js`), nested AA calls, and DB reads/writes — contains numerous unconditional `throw Error(...)` calls reachable with attacker-controlled input (e.g. `readLastStableMcUnit`, `readMcUnit`, `readUnit`, `handleTrigger`'s `"bad AA definition"` check, `"base AA not found"`, etc.). Because these are synchronous throws inside asynchronous callback chains rather than being routed through the `onDone`/`ROLLBACK` path, an attacker-supplied trigger/address combination that reaches one of these throws before the code reaches `conn.query("ROLLBACK", ...)` leaves the pooled connection with an open, uncommitted transaction (real inserted fake outputs, real state) instead of guaranteeing cleanup. This mirrors the OFBiz root cause precisely: a code path meant to run only after some implicit precondition (here, that unit/trigger validation already happened) is instead reachable directly and unauthenticated, and the reached logic performs real database mutation and privileged execution.

### Impact Explanation
An unauthenticated peer can force a full node to insert forged output rows (arbitrary `address`, arbitrary positive `amount`) into the real `outputs` table tied to the current last-stable MC unit and to execute arbitrary victim AAs' oscript code with attacker-chosen `trigger.data`/`trigger.address`/`trigger.outputs`. If the transaction is not cleanly rolled back (crash/exception before `ROLLBACK`, or the connection later reused with stale uncommitted state under load), fabricated balances become visible to that connection and any code relying on the `outputs` table for balance/spend calculation, i.e., supply inflation / unauthorized spending. Even absent a corrupted commit, this endpoint lets any peer force arbitrary victim AAs to fully execute against attacker-forged incoming payments/data without ever posting a real, validated, signed unit, which is exactly the "unauthenticated execution of screen-rendering[/business-logic] code" class from the CVE.

### Likelihood Explanation
`light/dry_run_aa` is reachable by any peer that can open an inbound light-client websocket connection to a full node (no login, no pairing, no unit signature required) — only `conf.bLight` and `ws.bOutbound` gate it, not authentication. Triggering arbitrary throws inside the multi-thousand-line `handleTrigger` state machine with crafted AA definitions/trigger data is plausible given the many `throw Error` statements reachable from attacker-controlled `arrDefinition`/`trigger` fields.

### Recommendation
- Ensure `dryRunPrimaryAATrigger`/`handleTrigger` never allow a synchronous `throw` to escape the `BEGIN`/`ROLLBACK` transaction boundary; wrap the entire dry-run pipeline in a try/catch that guarantees `ROLLBACK` and `conn.release()` even on unexpected errors.
- Avoid inserting fake rows directly into the production `outputs` table tied to the real last-stable MC unit; use an isolated/synthetic unit id (as is partially done for `trigger.unit`) so a failed rollback cannot pollute genuine consensus data.
- Consider rate-limiting/gating `light/dry_run_aa` and validating that any exception during dry-run is treated as a fatal, connection-discarding event rather than assuming rollback always occurs.

### Proof of Concept
1. Connect as an inbound light client to a full node (`conf.bServeAsHub`-less full node) without any authentication.
2. Send `{"command":"light/dry_run_aa","params":{"address": "<any real AA address>", "trigger": {"address": "<attacker address>", "outputs": {"base": 999999999}, "data": {...crafted to hit a throw inside handleTrigger, e.g. reference a base_aa that doesn't exist or malformed nested AA...}}}`.
3. Observe that `insertFakeOutputsIntoMcUnit` executes an `INSERT INTO outputs` against the real last stable MC unit before the crafted data causes a `throw Error(...)` deep in `handleTrigger`/`evaluateAA`, and confirm whether `ROLLBACK`/`conn.release()` in `dryRunPrimaryAATrigger`'s `onDone` is reached.

### Citations

**File:** network.js (L3939-3962)
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
			});
```

**File:** aa_composer.js (L224-270)
```javascript
function validateAATriggerObject(trigger, handle) {
	if (!ValidationUtils.isNonemptyObject(trigger))
		return handle("no trigger");
	if (!ValidationUtils.isNonemptyObject(trigger.outputs))
		return handle("no trigger outputs");
	if (!ValidationUtils.isValidAddress(trigger.address))
		return handle("bad trigger address");
	if ("max_aa_responses" in trigger && (!ValidationUtils.isNonnegativeInteger(trigger.max_aa_responses) || trigger.max_aa_responses > constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER))
		return handle("bad trigger max_aa_responses");
	if (ValidationUtils.hasFieldsExcept(trigger, ["address", "data", "outputs", "max_aa_responses"])) // initial_address and initial_unit cannot be separately set in a primary trigger
		return handle("unexpected trigger fields");
	if (string_utils.isTooBigObj(trigger, { lengthLimit: 10e3 }))
		return handle("trigger data is too big");
	try {
		if (trigger.data)
			string_utils.getJsonSourceString(trigger.data);
	}
	catch (e) {
		return handle("invalid trigger data: " + e);
	}
	var arrAssets = Object.keys(trigger.outputs).filter(function(asset) {return asset !== 'base'});
	if (arrAssets.length >= constants.MAX_MESSAGES_PER_UNIT)
		return handle("too many assets");
	if (!ValidationUtils.isPositiveInteger(trigger.outputs.base))
		return handle("no base payment");
	if (!arrAssets.every(function(asset){return ValidationUtils.isPositiveInteger(trigger.outputs[asset])}))
		return handle("invalid output amount")

	function checkAddressIsNotAA() {
		db.query("SELECT 1 FROM aa_addresses WHERE address=?", [trigger.address], rows => {
			if (rows.length)
				return handle("trigger address must not be an AA");
			else
				return handle();
		});
	}

	if (arrAssets.length === 0)
		return checkAddressIsNotAA();
	// we have to check that assets exist otherwise foreign key constraint would fail when inserting fake outputs
	db.query("SELECT 1 FROM assets WHERE unit IN (?)", [arrAssets], function(rows) {
		if (rows.length !== arrAssets.length)
			return handle("unknown asset");
		else
			checkAddressIsNotAA();
	});
}
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

**File:** aa_composer.js (L1702-1757)
```javascript
	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
				},
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
					saveStateVars();
					addUpdatedStateVarsIntoPrimaryResponse();
					onDone(objUnit, bBouncing ? error_message : false);
				}
			);
		});
	}
```
