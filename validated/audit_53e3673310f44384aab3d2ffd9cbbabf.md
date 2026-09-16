## Analysis: Analog to CVE‑2021‑1093 in ocore

CVE‑2021‑1093 describes an `assert()`-style statement reachable by an attacker that causes an application/process crash rather than a graceful error — i.e., a developer-added "this should never happen" check that turns into a remotely triggerable denial of service. The ocore codebase has this exact anti-pattern in the unit-validation pipeline: several `throw Error(...)` calls guard conditions the developers believed to be logically impossible, but they execute inside asynchronous DB-query/graph callbacks that are **not** part of the `async.series` error-first chain used by `validate()`. Any such throw becomes an uncaught exception, which is deliberately re-thrown by the global handler to kill the whole node process.

### Title
Attacker-reachable "impossible" assertions in double-spend/input validation crash the entire node process (DoS) - (File: `validation.js`)

### Summary
`validation.js`'s `checkForDoublespends()` and the payment-input validator in `validatePaymentInputsAndOutputs()` contain multiple `throw Error(...)` statements guarding conditions the authors consider unreachable ("unreachable code", "spending a stable temp-bad output", "more than 1 src output", etc.). These throws fire inside nested asynchronous callbacks (`conn.query`, `graph.determineIfIncludedOrEqual`) rather than being returned through the `callback`/`cb` error-first convention used everywhere else in the file. [1](#0-0)  Because a single crafted or gossiped unit from an unprivileged peer/wallet drives this code path via `network.js`'s `handleJoint`, and because the global `uncaughtException` handler re-throws to intentionally crash the process, an attacker who can construct a unit that hits one of these "impossible" branches can crash any full node that receives/validates it. [2](#0-1) 

### Finding Description
`validate()` runs unit validation for every posted/relayed joint under `mutex.lock`, invoking `validateMessages` → `validateMessage` → `validatePaymentInputsAndOutputs`/`validateSpendProofs` → `checkForDoublespends`. [3](#0-2) [4](#0-3) 

Inside `checkForDoublespends`, once a conflicting record is fetched from the DB, the code assumes:
1. The conflicting record's address must always be one of the current unit's author addresses — otherwise it `throw`s "conflicting … spent from another address?". [5](#0-4) 
2. If the conflicting unit is not included in ancestry and the address isn't already flagged as forked, it `throw`s "double spending … without double spending address?". [6](#0-5) 
3. If the conflicting unit is included but neither too-young nor "good" sequence, it `throw`s "unreachable code, conflicting …". [7](#0-6) 

Similarly, in `validatePaymentInputsAndOutputs`, transfer-type double-spend checks assume a stable output can never have `sequence === 'temp-bad'` and `throw Error("spending a stable temp-bad output " + input.unit)` if it does, and assume the source-output lookup can never return more than one row (`throw Error("more than 1 src output")`). [8](#0-7) 

None of these branches return through the `cb`/`callback` error path used consistently elsewhere in the same function — they use `throw` inside a `conn.query` or `graph.determineIfIncludedOrEqual` callback. That means the exception is not caught by any surrounding `try/catch` in `validate()`'s `async.series`, and surfaces as a Node.js "uncaught exception" on the event loop. `network.js` explicitly re-throws inside its `uncaughtException` handler "to avoid ending up in an inconsistent state," which terminates the entire process. [2](#0-1)  This is functionally identical to the CVE's "assert()-like statement… triggered by an attacker" causing "application exit… more severe than necessary."

The forking/nonserial-unit logic that populates `arrAddressesWithForkedPath`, `sequence`, and per-address conflict bookkeeping in `validateAuthor`/`checkSerialAddressUse` is intricate and mutates shared validation state across authors and units competing for the same address; an attacker who controls timing/ordering of competing double-spend units (fully within reach of any wallet holding a signing key, or any unit poster racing spends) can attempt to drive `checkForDoublespends` or the input validator into one of these "impossible" states. [9](#0-8) 

### Impact Explanation
A successful trigger crashes the receiving/validating node process entirely (not just rejecting a single bad unit), which is a "network unable to confirm new units" style outcome if replicated across multiple nodes that receive the same unit via gossip/relay (`forwardJoint`). Because `handleJoint` is invoked for both self-posted units and units received from peers, and because full nodes relay valid-looking joints to peers, a single malicious unit could plausibly propagate and crash many independent nodes before it is dropped, which is a concrete network-availability impact rather than a mere local nuisance. [10](#0-9) 

### Likelihood Explanation
Reaching these exact "impossible" states requires crafting specific double-spend / sequence-state conditions (racing conflicting spends of the same output/spend-proof, or manipulating stability/sequence transitions) that the validation authors did not expect to be reachable — hence they used `throw` instead of a handled error return. This requires non-trivial but plausible manipulation of unit ordering/parents by an unprivileged unit poster, since spend races and forked-address handling are core, attacker-influenced parts of DAG validation. No special network position, hub role, or leaked keys are needed — only the ability to post/broadcast crafted units, which any wallet or unit-poster has.

### Recommendation
Convert all "impossible" `throw Error(...)` assertions inside `checkForDoublespends` and `validatePaymentInputsAndOutputs` (and any similar asserts reachable from unit/message validation) into proper `callback`/`cb`-based `ifUnitError`/`ifJointError` results instead of throwing, so that unexpected-but-attacker-reachable states result in unit rejection rather than a full process crash. At minimum, wrap the validation pipeline's asynchronous callback chains so uncaught exceptions from these specific assertions are caught and translated into a normal validation failure instead of propagating to the global `uncaughtException` handler.

### Proof of Concept
A concrete PoC requires driving a real double-spend race: post unit A spending output O from address X, let it become included in the DAG; then post a conflicting unit B (also authored by X, or in a forked-address scenario) spending the same output/spend-proof O such that, when `checkForDoublespends` re-evaluates B against the already-processed conflicting record for A, the record's `sequence`/inclusion state lands outside `{'good' with bIncluded}`/`{forked address flagged}`, hitting the `throw Error("unreachable code, conflicting …")` or `throw Error("double spending … without double spending address?")` branch in `checkForDoublespends`. [11](#0-10)  Because this executes inside the `graph.determineIfIncludedOrEqual` query callback with no enclosing try/catch, it surfaces as an uncaught exception and is re-thrown by `network.js`'s handler, terminating the node process. [2](#0-1)

### Citations

**File:** validation.js (L118-153)
```javascript
function validate(objJoint, callbacks, external_conn) {
	
	var objUnit = objJoint.unit;
	if (typeof objUnit !== "object" || objUnit === null)
		throw Error("no unit object");
	if (!objUnit.unit)
		throw Error("no unit");
	
	console.log("\nvalidating joint identified by unit "+objJoint.unit.unit);
	
	if (!isStringOfLength(objUnit.unit, constants.HASH_LENGTH))
		return callbacks.ifJointError("wrong unit length");
	
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}

	const bGenesis = storage.isGenesisUnit(objUnit.unit);

	var bAA = false;
	if (objJoint.aa) {
		bAA = true;
		var aa_mci = objJoint.aa_mci;
		delete objJoint.aa;
		delete objJoint.aa_mci;
	}
	else {
		if (isArrayOfLength(objUnit.authors, 1) && !isNonemptyObject(objUnit.authors[0].authentifiers) && !objUnit.content_hash && !conf.bLight)
			return callbacks.ifTransientError("possible AA");
	}
	
```

**File:** validation.js (L425-443)
```javascript
				function(cb){
					profiler.stop('validation-skiplist');
					validateWitnesses(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateAATrigger(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateTpsFee(conn, objJoint, objValidationState, cb);
				},
				function(cb){
					profiler.start();
					validateAuthors(conn, objUnit.authors, objUnit, objValidationState, cb);
				},
				function(cb){
					profiler.stop('validation-authors');
					profiler.start();
					objUnit.content_hash ? cb() : validateMessages(conn, objUnit.messages, objUnit, objValidationState, cb);
				}
```

**File:** validation.js (L1304-1343)
```javascript
	function checkSerialAddressUse(){
		var next = (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) ? validateDefinition : checkNoPendingChangeOfDefinitionChash;
		findConflictingUnits(function(arrConflictingUnitProps){
			if (arrConflictingUnitProps.length === 0){ // no conflicting units
				// we can have 2 authors. If the 1st author gave bad sequence but the 2nd is good then don't overwrite
				objValidationState.sequence = objValidationState.sequence || 'good';
				return next();
			}
			var arrConflictingUnits = arrConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			breadcrumbs.add("========== found conflicting units "+arrConflictingUnits+" =========");
			breadcrumbs.add("========== will accept a conflicting unit "+objUnit.unit+" =========");
			objValidationState.arrAddressesWithForkedPath.push(objAuthor.address);
			objValidationState.arrConflictingUnits = (objValidationState.arrConflictingUnits || []).concat(arrConflictingUnits);
			bNonserial = true;
			var arrUnstableConflictingUnitProps = arrConflictingUnitProps.filter(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 0);
			});
			// findConflictingUnits() already excludes final-bad rows, so any stable row left here is a real, good competitor
			var bConflictsWithStableUnits = arrConflictingUnitProps.some(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 1);
			});
			if (objValidationState.sequence !== 'final-bad') // if it were already final-bad because of 1st author, it can't become temp-bad due to 2nd author
				objValidationState.sequence = bConflictsWithStableUnits ? 'final-bad' : 'temp-bad';
			var arrUnstableConflictingUnits = arrUnstableConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			// if we are (or already became, due to another author) final-bad, we are not a living competitor for this address either,
			// so there is no need to punish other pending units - they'll correctly resolve to 'good' on their own once stable
			if (objValidationState.sequence === 'final-bad')
				return next();
			if (arrUnstableConflictingUnits.length === 0)
				return next();
			conn.query("SELECT unit FROM units WHERE unit IN(?) AND +sequence='good'",[arrUnstableConflictingUnits],function(rows){
				if (rows.length > 0)
					objValidationState.arrUnitsGettingBadSequence = (objValidationState.arrUnitsGettingBadSequence || []).concat(rows.map(function(row){return row.unit}));
				// we don't modify the db during validation, schedule the update for the write
				objValidationState.arrAdditionalQueries.push(
				{sql: "UPDATE units SET sequence='temp-bad' WHERE unit IN(?) AND +sequence='good'", params: [arrUnstableConflictingUnits]});
				next();
				});
		});
	}
```

**File:** validation.js (L1661-1705)
```javascript
function checkForDoublespends(conn, type, sql, arrSqlArgs, objUnit, objValidationState, onAcceptedDoublespends, cb){
	conn.query(
		sql, 
		arrSqlArgs,
		function(rows){
			if (rows.length === 0)
				return cb();
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			async.eachSeries(
				rows,
				function(objConflictingRecord, cb2){
					if (arrAuthorAddresses.indexOf(objConflictingRecord.address) === -1)
						throw Error("conflicting "+type+" spent from another address?");
					if (conf.bLight) // we can't use graph in light wallet, the private payment can be resent and revalidated when stable
						return cb2(objUnit.unit+": conflicting "+type);
					graph.determineIfIncludedOrEqual(conn, objConflictingRecord.unit, objUnit.parent_units, function(bIncluded){
						if (bIncluded){
							var error = objUnit.unit+": conflicting "+type+" in inner unit "+objConflictingRecord.unit;

							// too young (serial or nonserial)
							if (objConflictingRecord.main_chain_index > objValidationState.last_ball_mci || objConflictingRecord.main_chain_index === null)
								return cb2(error);

							// in good sequence (final state); final-bad is excluded by the query and treated as non-existent
							if (objConflictingRecord.sequence === 'good')
								return cb2(error);

							throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit);
						}
						else{ // arrAddressesWithForkedPath is not set when validating private payments
							if (objValidationState.arrAddressesWithForkedPath && objValidationState.arrAddressesWithForkedPath.indexOf(objConflictingRecord.address) === -1)
								throw Error("double spending "+type+" without double spending address?");
							cb2();
						}
					});
				},
				function(err){
					if (err)
						return cb(err);
					onAcceptedDoublespends(cb);
				}
			);
		}
	);
}
```

**File:** validation.js (L2450-2458)
```javascript
							if (rows.length > 1)
								throw Error("more than 1 src output");
							if (rows.length === 0)
								return cb("input unit "+input.unit+" not found");
							var src_output = rows[0];
							var bStableInParents = (src_output.main_chain_index !== null && src_output.main_chain_index <= objValidationState.last_ball_mci);
							if (bStableInParents) {
								if (src_output.sequence === 'temp-bad')
									throw Error("spending a stable temp-bad output " + input.unit);
```

**File:** network.js (L1142-1147)
```javascript
function forwardJoint(ws, objJoint){
	[...wss.clients].concat(arrOutboundPeers).forEach(function(client) {
		if (client != ws && client.bSubscribed)
			sendJoint(client, objJoint);
	});
}
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
