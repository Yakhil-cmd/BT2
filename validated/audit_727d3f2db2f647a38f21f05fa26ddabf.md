### Title
Reachable assertion (`throw Error`) in payment-input validation crashes full node on stable temp-bad output - (File: validation.js)

### Summary
`validatePaymentInputsAndOutputs()` in `validation.js` contains hard `throw Error(...)` invariant checks that execute inside a `conn.query` callback while validating a `transfer` input of a payment message. If the invariant "a stable output must never have `sequence='temp-bad'`" is ever violated for a source output referenced by an incoming unit's input, the thrown error is not caught by any `try/catch` in the validation call chain and propagates out of the async callback, which in Node.js crashes the whole process.

### Finding Description
In `validatePaymentInputsAndOutputs`, when validating a `transfer`-type payment input, the code looks up the source output and asserts invariants about its state: [1](#0-0) 

Specifically:
```
if (rows.length > 1)
    throw Error("more than 1 src output");
...
if (bStableInParents) {
    if (src_output.sequence === 'temp-bad')
        throw Error("spending a stable temp-bad output " + input.unit);
    if (src_output.sequence === 'final-bad')
        return cb("spending a stable final-bad output " + input.unit);
}
```
Unlike the `final-bad` case, which is handled gracefully via `cb(...)` (a normal unit-error path), the `temp-bad` case is treated as an unrecoverable internal-invariant violation and unconditionally throws. This throw occurs inside the callback of `conn.query(...)`, i.e., inside an asynchronous database-driver callback, not inside the synchronous `try{...}` blocks used elsewhere in `validate()` (e.g., the outer joint-hash calculation at `validation.js:131-138`). There is no surrounding `try/catch` for this async callback, so a thrown `Error` here bubbles up through the event loop and is caught only by the global `process.on('uncaughtException', ...)` handler in `network.js`, which explicitly re-throws to crash the process: [2](#0-1) 

This is the same bug class as the reported grpc-swift issue: a reachable assertion/invariant check on attacker-influenced protocol state that is meant to never fire in correct operation, but if reachable, deterministically terminates the process, rather than being handled as an ordinary validation failure. This code path is reached directly from `validation.validate()`, which is called from `network.js`'s `handleJoint` on every unit received/posted (both light and full nodes), and also from `aa_composer.js`'s `validateAndSaveUnit` when validating AA response units. [3](#0-2) [4](#0-3) 

### Impact Explanation
If a `temp-bad`-sequenced output ever becomes stable in a node's local view (whether through a genuine consensus/implementation edge case, a database inconsistency from a prior code path, or a race in how `sequence` is finalized relative to `main_chain_index`/stability advancement), then any node that subsequently validates ANY unit spending that output — a payment that any unprivileged wallet/user can construct by referencing that unit/message_index/output_index as an input — will hit the `throw Error` and crash. Because validation is performed by every full node that receives the unit (via `handleJoint`/`broadcastJoint`), a single crafted unit can be broadcast network-wide, crashing every full node that processes it, which is a denial-of-service against network availability (nodes unable to confirm new units, in-flight requests dropped, and any pending AA/writer state at the moment of crash left in an undefined state until process restart and DB re-init).

### Likelihood Explanation
The likelihood hinges entirely on whether an unprivileged unit poster can actually cause a spendable output to be stable with `sequence='temp-bad'` while still being referenceable as a valid input target (`src_output.address` populated) in the `outputs` table. `temp-bad` sequence is set for units that are conflicting-but-not-yet-resolved (nonserial) during main-chain advancement in `main_chain.js`/`writer.js`; it is expected to be a transient state that gets resolved to `good` or `final-bad` before/at stabilization. Whether there is a code path (e.g., double-spend resolution edge cases, MC-stability re-evaluation ordering, or a race between output insertion and sequence update) that can leave a stable output permanently in `temp-bad` could not be fully confirmed within available tool budget — this would require tracing `main_chain.js` and `writer.js` sequence-transition logic in full, which was only partially retrieved before the session ended. The existence of the explicit, differentiated `throw` (vs. the graceful `cb()` used for the structurally similar `final-bad` case) strongly suggests the developers considered `temp-bad`-and-stable an "impossible" state whose violation is only guarded by an assertion rather than proper error handling — this is precisely the "reachable assertion" pattern from the CVE, but I could not conclusively prove a concrete external trigger for reaching this state within the current investigation.

### Recommendation
Replace the `throw Error("spending a stable temp-bad output " + input.unit)` with a graceful `cb(...)` unit-error return, matching the handling of `final-bad`, so that malformed or edge-case DB state results in a validation rejection instead of a process crash. More broadly, audit all `throw Error(...)` statements inside asynchronous `conn.query` callbacks reached from unit/AA/asset validation paths (there are several similar patterns, e.g. `validation.js:2417-2424`, `2451`, `591`/witnessing-input errors) and convert externally-reachable ones into recoverable error callbacks, reserving hard throws only for conditions that are provably unreachable from network input (e.g., truly internal logic bugs, not data reachable from a peer-supplied unit).

### Proof of Concept
A full working PoC could not be constructed without confirming a concrete path that stabilizes an output while leaving its unit's `sequence` as `'temp-bad'` (this requires deep knowledge of `main_chain.js` stability-advancement and nonserial-resolution logic that was not fully retrieved). Conceptually, the PoC would be:
1. Craft/observe (or induce via a double-spend race) a unit `U` whose `sequence` remains `'temp-bad'` after its output becomes stable (`main_chain_index <= last_ball_mci` for some later unit).
2. Post a new unit `V` with a `payment` message containing a `transfer` input `{ unit: U, message_index, output_index }` pointing at that stable output.
3. Broadcast `V` to the network; every full node that validates `V` executes `validation.js:2457-2458`, throws, and crashes via the `uncaughtException` handler in `network.js:4530-4543`.

Given the inability to confirm step 1's feasibility with certainty in this session, this finding should be treated as **medium-confidence** pending verification of whether `temp-bad`-and-stable is truly reachable; the code pattern itself (differentiated assert-vs-graceful-handling for structurally identical `final-bad`/`temp-bad` cases) is confirmed and directly analogous to the reported bug class.

### Citations

**File:** validation.js (L2443-2461)
```javascript
					conn.query(
						"SELECT amount, is_stable, sequence, address, main_chain_index, denomination, asset \n\
						FROM units \n\
						LEFT JOIN outputs ON units.unit=outputs.unit AND message_index=? AND output_index=? \n\
						WHERE units.unit=?",
						[input.message_index, input.output_index, input.unit],
						function(rows){
							if (rows.length > 1)
								throw Error("more than 1 src output");
							if (rows.length === 0)
								return cb("input unit "+input.unit+" not found");
							var src_output = rows[0];
							var bStableInParents = (src_output.main_chain_index !== null && src_output.main_chain_index <= objValidationState.last_ball_mci);
							if (bStableInParents) {
								if (src_output.sequence === 'temp-bad')
									throw Error("spending a stable temp-bad output " + input.unit);
								if (src_output.sequence === 'final-bad')
									return cb("spending a stable final-bad output " + input.unit);
							}
```

**File:** network.js (L1258-1261)
```javascript
				ifOk: async function(objValidationState, validation_unlock){
					clearHost();
					if (objJoint.unsigned)
						throw Error("ifOk() unsigned");
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
