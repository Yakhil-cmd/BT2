## Analog Found

### Title
Missing `return` after caught hash exception causes continued execution with corrupted state and duplicate callback invocation in private-payment handling - (File: network.js)

### Summary
`handleSavedPrivatePayments()` in `network.js` computes a hash of an attacker-supplied private-payment payload without properly gating subsequent use of the result on success, mirroring the CVE-2019-12382 bug class ("unchecked value from a failable operation, subsequently relied on"). When the hash computation throws, the error is logged and cleanup is *started*, but execution falls through into code that uses the now-undefined result and re-invokes the async `cb()` a second time.

### Finding Description
In `handleSavedPrivatePayments`, each row of `unhandled_private_payments` (populated from private-payment data sent by a paired peer/private-payment counterparty) is processed like this: [1](#0-0) 

```js
var validateAndSave = function(){
    var objHeadPrivateElement = arrPrivateElements[0];
    try {
        var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
    }
    catch (e) {
        console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
        if (ws)
            sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
        deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
    }
    var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
    privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, { ... });
};
```

There is no `return` statement after the `catch` block calls `deleteHandledPrivateChain(..., cb)`. `cb` is the `async.each` iteratee callback for this row. If `objectHash.getBase64Hash` throws (which happens whenever the head private element's `payload` cannot be hashed, e.g. it contains values `objectHash` cannot serialize/hash), execution:
1. calls `cb` once via `deleteHandledPrivateChain` inside the `catch` block,
2. continues to build `key` using an `undefined` `json_payload_hash`,
3. calls `privatePayment.validateAndSavePrivatePaymentChain(...)` again on the same, now partially-deleted, private chain, whose `ifOk`/`ifError` callbacks each independently call `deleteHandledPrivateChain(..., cb)` a second time.

This is directly analogous to the CVE's root cause: the result of a fallible operation (`kstrdup` / here, `getBase64Hash`) is not properly checked/gated before being relied upon further down the control flow, and the failure path does not stop subsequent processing.

### Impact Explanation
`cb` invoked twice for the same `async.each` item corrupts the completion accounting of `async.each`. Depending on the async library version this can throw an internal error (calling the final callback multiple times) or otherwise desynchronize the `saved_private` mutex lock/unlock cycle managed in `handleSavedPrivatePayments`. Because `network.js` installs a process-wide `uncaughtException` handler that deliberately re-throws to crash the process (`process.on('uncaughtException', ...) { ...; throw err; }`), any resulting unhandled exception from the corrupted async/mutex state terminates the node process, i.e., a wallet/hub node handling private payments becomes unavailable — a denial-of-service condition reachable purely by a private-payment counterparty sending a payload with a value that `objectHash.getBase64Hash` cannot process. [2](#0-1) 

### Likelihood Explanation
The trigger requires only that a peer or private-payment counterparty send an `arrPrivateElements` chain whose head element's `payload` causes `objectHash.getBase64Hash` to throw. Private payment chains and their JSON payloads are attacker-controlled inputs delivered via the wallet/hub messaging path (`unhandled_private_payments` is populated from data received from a peer), so no special privileges are required beyond being a pairing/private-payment counterparty.

### Recommendation
Add a `return;` (or otherwise short-circuit) at the end of the `catch` block in `validateAndSave` in `network.js` so that `key` computation and `privatePayment.validateAndSavePrivatePaymentChain(...)` are never invoked after a hash failure, guaranteeing `cb` is called exactly once per row.

### Proof of Concept
1. As a paired device / private-payment counterparty, construct a private-payment chain whose head element's `payload` includes a value that causes `objectHash.getBase64Hash` to throw (e.g., a payload field of an unsupported/malformed type that the hashing routine cannot serialize).
2. Send this chain so it is persisted to `unhandled_private_payments` and processed by `handleSavedPrivatePayments`.
3. The `try` block throws; the `catch` block calls `cb` via `deleteHandledPrivateChain`, then falls through and calls `privatePayment.validateAndSavePrivatePaymentChain` again, triggering a second `cb` invocation.
4. Repeated/duplicate `cb` calls destabilize `async.each`'s completion tracking, eventually surfacing as an uncaught exception that is re-thrown by the global `uncaughtException` handler, crashing the ocore process.

Note: I was not able to fully trace every downstream `async` library behavior for double-callback invocation (version-specific), so the exact crash mechanics (immediate throw vs. delayed corruption) could not be fully confirmed from static analysis alone; a Devin session with the ability to run the code would be needed to confirm the precise crash trigger.

### Citations

**File:** network.js (L2467-2504)
```javascript
					var validateAndSave = function(){
						var objHeadPrivateElement = arrPrivateElements[0];
						try {
							var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
						}
						catch (e) {
							console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
							if (ws)
								sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
							deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
						}
						var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
						privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
							ifOk: function(){
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'accepted'});
								if (row.peer) // received directly from a peer, not through the hub
									eventBus.emit("new_direct_private_chains", [arrPrivateElements]);
								assocNewUnits[row.unit] = true;
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								console.log('emit '+key);
								eventBus.emit(key, true);
							},
							ifError: function(error){
								console.log("validation of priv: "+error);
							//	throw Error(error);
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: error});
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								eventBus.emit(key, false);
							},
							// light only. Means that chain joints (excluding the head) not downloaded yet or not stable yet
							ifWaitingForChain: function(){
								console.log('waiting for chain: unit '+row.unit+', message '+row.message_index+' output '+row.output_index);
								cb();
							}
						});
					};
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
