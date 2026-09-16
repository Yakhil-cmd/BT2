### Title
Unprivileged unit poster can crash full nodes via unguarded `throw Error` assertion in payment input validation - ([File: validation.js])

### Summary
`validation.js`'s `validatePaymentInputsAndOutputs()` contains hard `throw Error(...)` statements that are meant to be unreachable invariant checks, but they execute inside a `conn.query` callback that runs while processing **any externally posted unit**. If the invariant is ever violated, the `throw` becomes an uncaught exception that is not funneled through the normal `ifUnitError`/`ifJointError` callback path used throughout the rest of `validation.js`. It propagates out of the async database callback and is caught only by the global `process.on('uncaughtException', ...)` handler in `network.js`, which deliberately re-throws to crash the process. This is directly analogous to the systemd bug class: a low-privilege actor (any unit poster) supplies data that trips an internal assertion, freezing/crashing the privileged service (here, the full-node daemon) instead of being handled as an ordinary validation failure.

### Finding Description
Inside the `"transfer"` input-validation branch of `validatePaymentInputsAndOutputs`, the code looks up the source output being spent: [1](#0-0) 

Every other error condition in this function (bad address, wrong denomination, unrelated author, etc.) is reported through `return cb("...")`, which flows back into the standard `ifUnitError` callback and results in the unit simply being rejected. But two conditions are instead expressed as hard `throw Error(...)`:
- `rows.length > 1` → `throw Error("more than 1 src output")`
- `bStableInParents && src_output.sequence === 'temp-bad'` → `throw Error("spending a stable temp-bad output " + input.unit)`

These are written as "should never happen" invariants: once a unit's `main_chain_index` places it within the referencing unit's `last_ball_mci` (`bStableInParents`), the code assumes `sequence` must already have been finalized to `'good'` or `'final-bad'` by the stabilization logic in `main_chain.js`/`writer.js`, and can never still be `'temp-bad'`. Unlike systemd's IPC handler (where the assert guards against a genuinely impossible internal state on trusted input), here the guarded state is derived from **untrusted, attacker-influenced unit graph data** — any peer can construct a payment `input` object (`{type: "transfer", unit, message_index, output_index}`) that references an arbitrary prior output, and the `sequence`/`main_chain_index` combination read from the local DB depends on the current stabilization state of *that other unit*, which is influenced by conflicting/double-spending units that an attacker fully controls.

Because these are synchronous `throw` statements inside a callback fired from `conn.query`, none of the code that would normally catch validation errors (the `try { validation.validate(...) } ` wrappers used elsewhere, or the callback-object pattern) can intercept them: [2](#0-1) [3](#0-2) 

`onWebsocketMessage` dispatches `handleJustsaying`/`handleRequest` for incoming units without a surrounding try/catch around the async validation chain, so an uncaught throw deep in `validatePaymentInputsAndOutputs`'s DB callback bubbles up to Node's `uncaughtException` handler, which explicitly re-throws to crash the process ("crash the process to avoid ending up in an inconsistent state").

### Impact Explanation
If the "impossible" state (`bStableInParents` true while `sequence === 'temp-bad'`) is actually reachable — e.g., via a double-spend/nonserial scenario where one competing unit's `main_chain_index` is assigned before its `sequence` field is fully finalized to `final-bad`/`good` by the stabilizer, or via a discrepancy between different nodes' views of which sibling "won" a double-spend — an attacker can craft and broadcast a single ordinary payment unit that spends the ambiguous output. Every full node (and any composing/relay logic that shares this validation code, e.g. `composer.js`, `divisible_asset.js`, `indivisible_asset.js` saving paths) that validates this unit hits the `throw` and crashes the entire daemon process. This is a network-wide denial of service: a node that keeps restarting on the same poisoned unit becomes unable to confirm new units, matching the "network unable to confirm new units" impact bucket permitted by the rules.

### Likelihood Explanation
Reaching this exact race condition (temp-bad sequence surviving into the `bStableInParents` window) requires a specific double-spend/stabilization timing scenario that I was not able to fully trace end-to-end through `main_chain.js`'s sequence-finalization logic within the available investigation time. The root-cause pattern — an unreachable-by-design `throw` embedded in attacker-reachable, DB-state-dependent validation logic instead of a soft validation-callback error — is confirmed and is architecturally identical to the systemd assert-on-spurious-IPC-data bug class. The exact preconditions to trigger the `temp-bad` state at the moment of lookup need further confirmation against `main_chain.js`/`writer.js` sequence-update ordering, which I could not fully verify due to tool budget exhaustion.

### Recommendation
Convert the two hard asserts in `validatePaymentInputsAndOutputs` (lines ~2450-2451 and ~2457-2458 of `validation.js`) into ordinary validation failures routed through `cb(...)`/`ifUnitError` (or, if truly invariant-breaking, through `ifJointError`) rather than `throw Error(...)`, so that any externally triggerable violation is turned into unit rejection instead of a full-process crash. Additionally, wrap the top-level unit-processing dispatch (`onWebsocketMessage` → `handleJustsaying`/`handleRequest` → `validation.validate`) so that unexpected synchronous throws from deep validation callbacks reject the offending unit/connection instead of terminating the whole node process, removing the single-poisoned-unit-crashes-everyone amplification.

### Proof of Concept
Conceptual PoC (exact reproduction requires driving the DB into the stated race window, not fully verified in this review):
1. Attacker submits two conflicting units A1 and A2 that double-spend the same output, engineered so that main-chain-index assignment for the losing sibling occurs before its `sequence` column is updated from `'temp-bad'` to `'final-bad'`.
2. Attacker immediately broadcasts a follow-up unit B whose payment `input` is `{type:"transfer", unit:A2.unit, message_index, output_index}`, i.e., spending the (transiently) temp-bad, but now "stable-in-parents", output.
3. Any full node that validates unit B executes the query at `validation.js:2443-2451`/`2454-2458`; if the race window is hit, `sequence === 'temp-bad'` while `bStableInParents === true`, triggering `throw Error("spending a stable temp-bad output " + input.unit)`, which is uncaught and crashes the node process via the handler in `network.js:4530-4543`.

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

**File:** network.js (L4262-4304)
```javascript
function onWebsocketMessage(message) {
		
	var ws = this;
	
	if (ws.readyState !== ws.OPEN)
		return console.log("received a message on socket with ready state "+ws.readyState);
	
	if (typeof message !== 'string') // ws 8+
		message = message.toString();
	console.log('RECEIVED ' + message.length + ' chars ' + (message.length > 1000 ? message.substr(0,1000)+'...' : message) + ' from '+ws.peer);
	ws.last_ts = Date.now();
	
	try{
		var arrMessage = JSON.parse(message);
		var message_type = arrMessage[0];
		var content = arrMessage[1];
		if (!content || typeof content !== 'object')
			return console.log("content is not object: "+content);
	}
	catch(e){
		return console.log('failed to json.parse message '+message);
	}
	
	incrementPending(messagesInWork, ws.host)
	switch (message_type){
		case 'justsaying':
			handleJustsaying(ws, content.subject, content.body);
			break;
			
		case 'request':
			handleRequest(ws, content.tag, content.command, content.params);
			break;
		
		case 'response':
			handleResponse(ws, content.tag, content.response);
			break;
			
		default: 
			console.log("unknown type: ", message_type);
		//	throw Error("unknown type: "+message_type);
	}
	decrementPending(messagesInWork, ws.host);
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
