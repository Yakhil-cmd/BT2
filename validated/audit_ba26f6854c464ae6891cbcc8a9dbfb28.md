## Analog Found: Uncaught assertion-style `throw` in payment-input validation crashes the node (DoS)

The Jasper CVE is a classic **"assertion failure on attacker-controlled data crashes the process"** bug class. The `ocore--011` codebase has the same pattern in the untrusted-unit validation path: instead of returning a validation error through the normal `callback`/`cb` mechanism, several code paths inside `validatePaymentInputsAndOutputs` use a bare `throw Error(...)` when an "impossible" invariant about a spent output's sequence/state is violated. Since `validation.validate()` is invoked directly on every unit received from the network/API without a surrounding try/catch at this depth, an uncaught `throw` here propagates out of the async DB callback and crashes the node process — a network-wide denial of service if triggered against multiple/all full nodes, exactly mirroring the "specific crafted file causes assertion failure / DoS" pattern of CVE-2024-31744.

### Title
Uncaught `throw` on unexpected `src_output.sequence`/row state in payment-input validation crashes full nodes (assertion-failure DoS) - (File: `validation.js`)

### Summary
`validatePaymentInputsAndOutputs()` validates the `transfer` inputs of every incoming unit (base or asset payment) by looking up the referenced source output and checking its stored `sequence`/row-count invariants. Several of these checks use `throw Error(...)` rather than the callback-based error path used everywhere else in the same function, e.g.: [1](#0-0) 

```js
if (rows.length > 1)
    throw Error("more than 1 src output");
...
if (bStableInParents) {
    if (src_output.sequence === 'temp-bad')
        throw Error("spending a stable temp-bad output " + input.unit);
```

`bStableInParents` and `src_output.sequence` are derived purely from database state that reflects the history of previously-received units, which is itself influenced by attacker-supplied, adversarially-ordered units (double-spends, nonserial competitors, etc.) via `checkSerialAddressUse()` and `handleNonserialUnits()`: [2](#0-1) [3](#0-2) 

The code assumes that by the time a unit is "stable in parents" its `sequence` can only be `good` or `final-bad` (never `temp-bad`), and treats a violation of that assumption as fatal to the whole process rather than as a rejectable unit error.

### Finding Description
The throwing checks are reached from `network.js`'s `handleJoint` → `validation.validate()` → `validateMessages` → `validatePaymentInputsAndOutputs`, which is the exact code path used for **every unit posted by any peer or light client, including a freshly-composed, unprivileged payment unit**: [4](#0-3) 

Unlike `ifUnitError`, which lets `handleJoint` gracefully reject the unit and continue operating, a `throw` inside the `conn.query(...)` result callback at line 2450/2457 is not caught by the `async.series` machinery in `validateAuthors`/`validateMessages`/`validate()`, and bubbles up as an unhandled exception in the process's event loop, crashing the node (same mechanism as `network.js:1279` comment "if it would crash, let it crash now" acknowledges elsewhere for AA dry-runs, but here it is unconditional and unguarded for ordinary payments).

The invariant being asserted ("a stable output's sequence is never `temp-bad`") depends on the correctness of the nonserial-resolution logic in `main_chain.js`'s `handleNonserialUnits`/`findStableConflictingUnits` and on `writer.js`'s handling of `arrAdditionalQueries` that flips previously-`good` competing units to `temp-bad`: [5](#0-4) 

Any edge case that leaves a `main_chain_index`-assigned output with a lingering `temp-bad` sequence when a later, ordinary unit spends it (e.g., via a race between multiple double-spending branches, an AA-triggered branch, or a not-yet-covered nonserial-resolution edge case) causes the assertion to fire on that later unit's validation — turning what should be a `false` validation result into a process-terminating crash. This is precisely the same bug class as jasper's `jpc_streamlist_remove` assertion failure: a defensive `assert`/`throw` guarding an invariant that a malicious/adversarial input sequence can actually violate.

### Impact Explanation
A crash here is not a benign "unit rejected" outcome — it terminates the hub/node process. If reachable, an attacker can repeatedly post crafted double-spend/competing units designed to leave a spent output in the vulnerable state and then spend it in a follow-up unit, crashing any full node (and hubs) that processes the sequence, which satisfies the "network unable to confirm new units" impact bar (mass, repeatable node crash via unit propagation), analogous to how the Jasper bug lets a single malicious file DoS any consumer that decodes it.

### Likelihood Explanation
Reaching the specific state requires orchestrating multiple conflicting/double-spend units so that the nonserial-resolution invariant is violated — this is more intricate than a single-message trigger, so it is not a trivial one-shot crash, but it is fully reachable by an unprivileged unit poster with no special network position, using only standard DAG unit posting (no p2p/hub-malicious-peer / TLS / operator access needed), which keeps it in scope per the rules. The `throw` statements themselves are unconditionally fatal once the (attacker-influenced) precondition is met, so likelihood is bounded only by the difficulty of engineering the double-spend/nonserial sequence, not by any additional privilege.

### Recommendation
Replace all `throw Error(...)` invariant checks inside `validatePaymentInputsAndOutputs` (and structurally similar ones in `main_chain.js`'s `markMcIndexStable`/`handleNonserialUnits`) that are reachable from untrusted unit content with graceful `cb("...")`/`callback("...")` calls that flow through `ifUnitError`, so a violated invariant results in unit rejection instead of node crash. Additionally, wrap `validation.validate()` invocation paths in `network.js` with defensive error handling (e.g., catching synchronous throws from the validation pipeline) so that even genuinely unexpected internal-invariant violations degrade to "reject unit" rather than "crash process."

### Proof of Concept
Conceptually:
1. Attacker crafts unit `A` and a conflicting double-spend competitor `B` from the same address so that `checkSerialAddressUse()` marks one of them `temp-bad`: [6](#0-5) 
2. Attacker manipulates ordering/stabilization (e.g., via additional forked/competing units across multiple MCIs) to reach a state where the resolution in `handleNonserialUnits` does not update that output's `sequence` away from `temp-bad` before its containing unit's MCI is reported as `main_chain_index <= last_ball_mci` for a later unit under validation.
3. Attacker posts unit `C` that spends the affected output as a `transfer` input.
4. `validatePaymentInputsAndOutputs` evaluates `bStableInParents === true` and `src_output.sequence === 'temp-bad'`, hitting: [7](#0-6) 
`throw Error("spending a stable temp-bad output " + input.unit);` — crashing the receiving node instead of rejecting unit `C`.

### Citations

**File:** validation.js (L1322-1327)
```javascript
			var bConflictsWithStableUnits = arrConflictingUnitProps.some(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 1);
			});
			if (objValidationState.sequence !== 'final-bad') // if it were already final-bad because of 1st author, it can't become temp-bad due to 2nd author
				objValidationState.sequence = bConflictsWithStableUnits ? 'final-bad' : 'temp-bad';
			var arrUnstableConflictingUnits = arrUnstableConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
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

**File:** main_chain.js (L1318-1350)
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
```

**File:** network.js (L1174-1189)
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
```

**File:** writer.js (L59-73)
```javascript
		for (var i=0; i<objValidationState.arrAdditionalQueries.length; i++){
			var objAdditionalQuery = objValidationState.arrAdditionalQueries[i];
			conn.addQuery(arrQueries, objAdditionalQuery.sql, objAdditionalQuery.params);
			breadcrumbs.add('====== additional query '+JSON.stringify(objAdditionalQuery));
			if (objAdditionalQuery.sql.match(/temp-bad/)){
				var arrUnstableConflictingUnits = objAdditionalQuery.params[0];
				breadcrumbs.add('====== conflicting units in additional queries '+arrUnstableConflictingUnits.join(', '));
				arrUnstableConflictingUnits.forEach(function(conflicting_unit){
					var objConflictingUnitProps = storage.assocUnstableUnits[conflicting_unit];
					if (!objConflictingUnitProps)
						return breadcrumbs.add("====== conflicting unit "+conflicting_unit+" not found in unstable cache"); // already removed as uncovered
					if (objConflictingUnitProps.sequence === 'good')
						objConflictingUnitProps.sequence = 'temp-bad';
				});
			}
```
