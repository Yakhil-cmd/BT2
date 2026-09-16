### Title
Unhandled `throw Error` on temp-bad stable input during payment validation causes network-wide node crash - (File: validation.js)

### Summary
`validatePaymentInputsAndOutputs()` in `validation.js` treats certain internal state inconsistencies as "impossible" and reacts to them with a synchronous `throw Error(...)` instead of returning a validation error via the `cb()` callback. Because this code executes inside a DB-query callback invoked from `async.forEachOfSeries`, any thrown exception is not caught by the surrounding `validation.validate()` logic and escapes as an uncaught exception. `network.js` installs a global `process.on('uncaughtException', ...)` handler that deliberately re-throws to crash the node process. An unprivileged unit poster who can engineer a payment input that references a source output whose `sequence` is `'temp-bad'` while appearing "stable in parents" reaches this `throw`, crashing every full node that validates the unit — analogous to CVE-2017-10919/XSA-223, where mishandled event/interrupt state caused an unrecoverable hypervisor crash.

### Finding Description
In the "transfer" input branch of `validatePaymentInputsAndOutputs`, after looking up the source output: [1](#0-0) 
```
var src_output = rows[0];
var bStableInParents = (src_output.main_chain_index !== null && src_output.main_chain_index <= objValidationState.last_ball_mci);
if (bStableInParents) {
    if (src_output.sequence === 'temp-bad')
        throw Error("spending a stable temp-bad output " + input.unit);
    if (src_output.sequence === 'final-bad')
        return cb("spending a stable final-bad output " + input.unit);
}
```
This `throw` is a "should never happen" assertion, based on the invariant that once a unit is *effectively* stable (its `main_chain_index` is at or before `last_ball_mci`), its `sequence` should already have been resolved from `'temp-bad'` to either `'good'` or `'final-bad'` by `handleNonserialUnits()` in `main_chain.js`, which runs during `markMcIndexStable()`: [2](#0-1) 

The problem is that `main_chain_index` assignment (part of ordinary main-chain computation) and `sequence` finalization (`good`/`final-bad`, performed only at stabilization time via `handleNonserialUnits`) are two separate steps that do not happen atomically. A unit's `sequence` is set to `'temp-bad'` as soon as another, currently-unstable unit is found to conflict with it — this write happens immediately during validation of the conflicting unit via `objValidationState.arrAdditionalQueries`: [3](#0-2) 
```
if (objValidationState.sequence !== 'final-bad')
    objValidationState.sequence = bConflictsWithStableUnits ? 'final-bad' : 'temp-bad';
...
objValidationState.arrAdditionalQueries.push(
{sql: "UPDATE units SET sequence='temp-bad' WHERE unit IN(?) AND +sequence='good'", params: [arrUnstableConflictingUnits]});
```
`main_chain_index` can be assigned to a unit while it progresses through main-chain ordering before its `sequence` is finally resolved at the `handleNonserialUnits` stabilization step for that MCI. If a crafted unit is submitted whose `last_ball`/`last_ball_unit` reference is set so that `last_ball_mci >= src_output.main_chain_index` (satisfying `bStableInParents`) for an output belonging to a unit that has already been assigned that MCI but is still transiently marked `'temp-bad'` (its owning unit was flagged bad by a conflicting sibling but the stabilization sweep hasn't run/committed yet), the assertion is violated and the uncaught `throw` fires deep inside async DB callbacks, bypassing all `try/catch` in `validate()`.

### Impact Explanation
The exception is not contained by `validation.js`'s `async.series`/`async.eachSeries` error-handling (which only handles values passed to `cb(err)`, not thrown exceptions), so it propagates to `network.js`'s global handler, which intentionally re-throws to crash the process: [4](#0-3) 
```
process.on('uncaughtException', (err) => {
    ...
    throw err; // crash the process to avoid ending up in an inconsistent state
});
```
Since every honest full node independently validates every newly broadcast unit, a single crafted unit that hits this code path would crash all full nodes that process it near-simultaneously, halting confirmation of new units network-wide until node operators manually intervene — a severe availability impact consistent with the CVE's "denial of service" bug class.

### Likelihood Explanation
Triggering the exact race between MCI assignment and sequence finalization for a targeted output requires careful timing of a conflicting double-spend unit and precise construction of `last_ball`/`last_ball_unit`/`parent_units` in the spending unit so the exploited output appears `bStableInParents` while its owning unit is still `'temp-bad'`. This is non-trivial to engineer deterministically but does not require any privileged network position, peer compromise, or leaked keys — only ordinary unit posting capability, placing it within the "unprivileged unit poster" reachable surface defined by the exercise.

### Recommendation
Replace the `throw Error("spending a stable temp-bad output ...")` assertion with a graceful validation failure (`return cb(...)`), matching the handling of the adjacent `'final-bad'` case, so that any occurrence of this state (whether from the race condition described or any other cause) is treated as a normal unit-validation error rather than crashing the process. Additionally, review other similar defensive `throw Error(...)` assertions inside unit-validation-reachable async callbacks (e.g., `validation.js:2450` "more than 1 src output", `2475` "src output amount is not a number", `2299` "spend proof didn't help", `2217` "more than one record per denomination") to ensure none of them can be triggered by adversarial input and, where uncertain, convert them to soft validation errors delivered via `callback`/`cb` instead of `throw`.

### Proof of Concept
1. Attacker controls (or has previously used) address A whose funds are held in output O of unit U1.
2. Attacker crafts two conflicting units, U2 and U3, both spending from address A's history such that U2 and U3 double-spend against each other, causing whichever is processed second to be flagged `'temp-bad'` via the `checkSerialAddressUse` logic in `validation.js:1304-1343`, before either has stabilized.
3. Concurrently (or immediately after), attacker crafts unit U4 that spends output O of U1, wiring `parent_units`/`last_ball`/`last_ball_unit` so that `last_ball_mci` is at or beyond `main_chain_index` already assigned to U1 (satisfying `bStableInParents`), while U1's `sequence` field in the `units` table is still `'temp-bad'` due to step 2's pending double-spend resolution having not yet been committed by `handleNonserialUnits`.
4. When any full node validates U4, it hits `validation.js:2457-2458`'s `throw Error("spending a stable temp-bad output " + input.unit)`, which propagates uncaught to `network.js`'s `process.on('uncaughtException', ...)` handler, crashing the node process.
5. Since all full nodes on the network independently validate U4 upon receipt, the crash affects the network broadly, halting confirmation of new units until nodes are manually restarted.

### Citations

**File:** validation.js (L1325-1339)
```javascript
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
```

**File:** validation.js (L2454-2461)
```javascript
							var src_output = rows[0];
							var bStableInParents = (src_output.main_chain_index !== null && src_output.main_chain_index <= objValidationState.last_ball_mci);
							if (bStableInParents) {
								if (src_output.sequence === 'temp-bad')
									throw Error("spending a stable temp-bad output " + input.unit);
								if (src_output.sequence === 'final-bad')
									return cb("spending a stable final-bad output " + input.unit);
							}
```

**File:** main_chain.js (L1318-1351)
```javascript
	function handleNonserialUnits(){
	//	console.log('handleNonserialUnits')
		conn.query(
			"SELECT * FROM units WHERE main_chain_index=? AND sequence!='good' ORDER BY unit", [mci], 
			function(rows){
				var arrFinalBadUnits = [];
				async.eachSeries(
					rows,
					function(row, cb){
						if (row.sequence === 'final-bad'){
							arrFinalBadUnits.push(row.unit);
							return row.content_hash ? cb() : setContentHash(row.unit, cb);
						}
						// temp-bad
						if (row.content_hash)
							throw Error("temp-bad and with content_hash?");
						findStableConflictingUnits(row, function(arrConflictingUnits){
							var sequence = (arrConflictingUnits.length > 0) ? 'final-bad' : 'good';
							console.log("unit "+row.unit+" has competitors "+arrConflictingUnits+", it becomes "+sequence);
							conn.query("UPDATE units SET sequence=? WHERE unit=?", [sequence, row.unit], function(){
								if (sequence === 'good')
									conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], function(){
										storage.assocStableUnits[row.unit].sequence = 'good';
										cb();
									});
								else{
									arrFinalBadUnits.push(row.unit);
									// treat this unit as a non-existent competitor from now on
									conn.query("UPDATE inputs SET is_unique=NULL WHERE unit=?", [row.unit], function(){
										setContentHash(row.unit, cb);
									});
								}
							});
						});
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
