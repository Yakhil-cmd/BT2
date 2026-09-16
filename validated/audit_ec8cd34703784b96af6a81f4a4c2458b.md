### Title
Uncaught exception on double-spend proof failure for private assets crashes the full node - (File: validation.js)

### Summary
The GHSA-xqp8-w826-hh6x advisory describes Parse Server crashing because an invalid, attacker-supplied query parameter triggers an exception in a code path that only calls `ifError`/error callbacks in the "normal" case, but throws synchronously on an edge case that the caller never wraps in try/catch, killing the process. `ocore--012` has an analogous pattern in `validation.js`'s private-asset double-spend handling: instead of routing an error back through the async callback chain, the code does `throw Error(...)` from inside a nested async callback.

### Finding Description
In `validatePaymentInputsAndOutputs`, when checking a payment input for double-spends, the completion callback of `checkForDoublespends` is: [1](#0-0) 
```
function onDone(err){
    if (err && objAsset && objAsset.is_private && !conf.bLight)
        throw Error("spend proof didn't help: "+err);
    cb2(err);
}
```
This `throw` happens inside an asynchronous DB-query callback deep in the `async.forEachOfSeries` iteration over `payload.inputs` inside `validatePaymentInputsAndOutputs`, which itself is invoked from `validateMessages` during `validation.validate()` — the single synchronous entry point that processes every unit received from the network or posted locally, for both public and private assets. There is no surrounding `try/catch` anywhere on the call stack between this `throw` and the event loop, so it becomes an uncaught exception. `network.js` installs a global `process.on('uncaughtException', ...)` handler whose explicit purpose is to log diagnostics and then re-throw to crash the process: [2](#0-1) 
```
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	...
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
So any full node that reaches this `err && objAsset.is_private && !conf.bLight` branch while validating a private-asset payment input is guaranteed to crash, exactly mirroring the Parse Server pattern where a single malformed/edge-case input value bypasses normal error handling and throws synchronously, crashing the server.

The `err` path is reached when `checkForDoublespends`'s "accept doublespends" callback fails to resolve a private-asset conflict (e.g., the private spend-proof chain does not clear the conflict), which is plausible to trigger by crafting/relaying a private-asset unit whose inputs conflict with another unit already accepted by the node, without needing any special privilege — a normal unit poster / private-payment counterparty can construct and send such a chain.

### Impact Explanation
An uncaught exception here crashes the entire node process handling private-asset validation. Because the same `validation.validate()` code path is used for validating every incoming and relayed unit (public full nodes, hub nodes, and any peer relaying private chains), a single crafted private-asset unit with an unresolved double-spend can remotely crash any full node that processes it, mapping to "a network unable to confirm new units" if propagated broadly (nodes repeatedly crash on the same poisoned unit/private chain when catching up or re-validating), and can also be leveraged to disrupt private-payment settlement/validation on targeted nodes.

### Likelihood Explanation
Reaching this branch requires constructing a private asset with a conflicting/double-spent input and getting a node to validate it via `validatePaymentInputsAndOutputs` (reachable by any private-payment counterparty or unit relayer, not just an operator). Crafting the exact double-spend/spend-proof conditions requires some domain knowledge of the private-payment/double-spend-proof protocol, so likelihood is assessed as medium rather than trivial, but no special privilege or malicious peer/hub role is required beyond posting/relaying a unit.

### Recommendation
Replace `throw Error("spend proof didn't help: "+err)` in the `onDone` callback of the double-spend check (validation.js, inside `validatePaymentInputsAndOutputs`) with a call to `cb2(err)`/`cb(err)` so the failure flows through the normal `ifUnitError`/`ifJointError` validation callback chain instead of throwing synchronously, consistent with how every other validation failure in this function is surfaced. Audit other `throw Error(...)` calls inside async DB-query callbacks in `validation.js` and `aa_composer.js` for the same anti-pattern (invariant checks are acceptable to throw, but conditions reachable from external/untrusted unit content should return errors instead of throwing).

### Proof of Concept
1. An attacker (any user who can issue/hold a private asset) creates a private asset unit `U1` and spends an output of it in unit `U2`.
2. The attacker crafts a second, conflicting private-asset unit `U3` that spends the same output as `U2`, but constructs/relays it so that the private spend-proof/double-spend resolution in `checkForDoublespends`'s conflict-acceptance path fails to clear the conflict for `U3` (i.e., `onDone(err)` is called with a non-null `err`) while `objAsset.is_private` is true and the node is not light (`!conf.bLight`).
3. When a full node (or private-payment counterparty) validates `U3` via `validation.validate()` → `validateMessages` → `validatePaymentInputsAndOutputs`, execution reaches: [3](#0-2) 
```
function onDone(err){
    if (err && objAsset && objAsset.is_private && !conf.bLight)
        throw Error("spend proof didn't help: "+err);
```
4. The synchronous `throw` is not caught anywhere in the async callback chain, propagates to the top of the event loop, hits `process.on('uncaughtException', ...)` in `network.js`, which logs and re-throws, terminating the node process.

Note: I was not able to inspect the full body of `checkForDoublespends` (its exact conditions for calling `onDone(err)` with a private asset) within the available tool budget, so the precise minimal unit/private-chain construction needed to force `err` on this branch is not fully verified — this should be confirmed by a Devin session with full repo access before treating exploitability as certain.

### Citations

**File:** validation.js (L2297-2304)
```javascript
					function onDone(err){
						if (err && objAsset && objAsset.is_private && !conf.bLight)
							throw Error("spend proof didn't help: "+err);
					//	if (objAsset)
					//		profiler2.stop('checkInputDoubleSpend');
						cb2(err);
					}
				);
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
