### Title
Missing `return` after failed digest computation causes double-invocation of async callback and node crash in private payment reprocessing - ([File: network.js])

### Summary
In `handleSavedPrivatePayments()` → `validateAndSave()`, a `try/catch` around the private-payment payload digest computation (`objectHash.getBase64Hash`) fails to `return` after handling the error, letting execution fall through into code that re-processes the same private element and invokes the `async.each` iteration callback a second time.

### Finding Description
`network.js` reprocesses private payments that were previously queued in `unhandled_private_payments` (e.g. because the chain wasn't linked/stable yet for a light client, or because it arrived out of order). For each row, `validateAndSave()` first computes a deterministic hash of the head element's payload to build an event key: [1](#0-0) 

```
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
        ifOk: function(){ ...; deleteHandledPrivateChain(..., cb); ... },
        ifError: function(error){ ...; deleteHandledPrivateChain(..., cb); ... },
        ifWaitingForChain: function(){ ...; cb(); }
    });
};
```

`objectHash.getBase64Hash` calls `getJsonSourceString`/`getSourceString` (`string_utils.js`), which throw on malformed but attacker-controllable payload shapes — e.g. an empty object/array (when `bAllowEmpty` is false for the relevant code path), a string containing a `\x00` byte, or an `undefined` value nested in the payload: [2](#0-1) [3](#0-2) 

When such a payload is stored (via `network.js` `handleOnlinePrivatePayment`/`savePrivatePayment`, reachable from a paired device or counterparty sending `private_payments`/`private_payment` messages — see `wallet.js` `handlePrivatePaymentChains`) and later reprocessed by `handleSavedPrivatePayments`, the `try` block throws, the `catch` branch calls `deleteHandledPrivateChain(...)` (which itself asynchronously invokes `cb`), but — because there is no `return` — execution continues to the line below, computing `key` with an `undefined` `json_payload_hash`, and unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain(...)` again on the same `arrPrivateElements`. That call’s `ifOk`/`ifError`/`ifWaitingForChain` handlers each also eventually invoke `cb()`. The net effect is that the single `async.each` iteration callback `cb` for this row is invoked twice (once from `deleteHandledPrivateChain`, once from the second validation path). [4](#0-3) 

### Impact Explanation
Most modern versions of `async` throw a synchronous exception ("Callback was already called") when the same iteratee callback is invoked more than once within `async.each`/`eachSeries`. This exception is not caught by any surrounding handler here, so it propagates up as an uncaught exception, crashing the Node.js process running the wallet/hub. Since `handleSavedPrivatePayments` is periodically invoked and driven by attacker-supplied stored payloads (private payment chains received from any paired device or private-payment counterparty), a remote peer that is a normal, unprivileged private-payment counterparty can repeatedly trigger this crash on a victim's wallet or hub process, denying that node's ability to process further payments/units (a persistent crash loop / DoS), which is analogous in bug class to the Wireshark CVE-2019-10901 crash caused by improper handling of a digest field.

### Likelihood Explanation
Any device that can send a `private_payment`/`private_payments` message (a paired correspondent, as used by the wallet/hub protocol) can construct a payload whose JSON/source-string serialization throws (empty object/array, a string containing a NUL byte, `undefined` values, etc.), and, because it isn't fully validated before being queued to `unhandled_private_payments`, this reaches the vulnerable reprocessing path deterministically once `handleSavedPrivatePayments` runs on it. No special privileges beyond being a message-sending peer/device are required, making the likelihood high for any node that accepts private payments.

### Recommendation
Add a `return` immediately after handling the exception in the `catch` block of `validateAndSave()` in `network.js`, so that `deleteHandledPrivateChain(...)` is the only path that invokes `cb`, and the subsequent `validateAndSavePrivatePaymentChain` call is not reached when hash computation fails:
```js
catch (e) {
    console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
    if (ws)
        sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
    return deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
}
```
Additionally, validate the shape of `objPrivateElement.payload` (no empty objects/arrays, no NUL bytes, no `undefined`) before persisting it to `unhandled_private_payments`, so malformed private payments are rejected early rather than stored for later reprocessing.

### Proof of Concept
1. As a paired device/correspondent, send a `private_payments` message whose head private element's `payload` is crafted so that `objectHash.getBase64Hash(payload, true)` throws when eventually evaluated — e.g. a `payload` containing a key with a `\x00` character, or with a value of `undefined`/`null` in a nested field that survives JSON transport oddities, or an empty nested array/object where `bAllowEmpty` is not set for that call path.
2. Ensure the chain is queued into `unhandled_private_payments` rather than immediately validated (e.g., light client scenario where `arrPrivateElements.length > 1` and not yet linked, per `network.js:2404-2410`, or a race where `ifWaitingForChain`/`ifKnownUnverified` is hit).
3. Trigger reprocessing via `handleSavedPrivatePayments()` (called periodically/on new unit events).
4. Observe the `getBase64Hash` call throw inside `validateAndSave`, the `catch` block run without returning, `privatePayment.validateAndSavePrivatePaymentChain` being invoked a second time on the same element, and `cb` being invoked twice for the same `async.each` iteration — causing an uncaught "Callback was already called" exception that crashes the Node process.

### Citations

**File:** network.js (L2459-2519)
```javascript
			async.each( // handle different chains in parallel
				rows,
				function(row, cb){
					var arrPrivateElements = JSON.parse(row.json);
					var ws = getPeerWebSocket(row.peer);
					if (ws && ws.readyState !== ws.OPEN)
						ws = null;
					
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
					
					if (conf.bLight && arrPrivateElements.length > 1 && !row.linked)
						updateLinkProofsOfPrivateChain(arrPrivateElements, row.unit, row.message_index, row.output_index, cb, validateAndSave);
					else
						validateAndSave();
					
				},
				function(){
					unlock();
					var arrNewUnits = Object.keys(assocNewUnits);
					if (arrNewUnits.length > 0)
						eventBus.emit("new_my_transactions", arrNewUnits);
				}
			);
		});
```

**File:** string_utils.js (L11-20)
```javascript
function getSourceString(obj) {
	var arrComponents = [];
	function extractComponents(variable){
		if (variable === null)
			throw Error("null value in "+JSON.stringify(obj));
		switch (typeof variable){
			case "string":
				if (variable.includes(STRING_JOIN_CHAR))
					throw Error("00 byte in string value in " + JSON.stringify(obj));
				arrComponents.push("s", variable);
```

**File:** string_utils.js (L220-246)
```javascript
function getJsonSourceString(obj, bAllowEmpty) {
	let cache = new WeakMap();  // object to stringified result
	function stringify(variable){
		if (variable === null)
			throw Error("null value in "+JSON.stringify(obj));
		switch (typeof variable){
			case "string":
				return toWellFormedJsonStringify(variable);
			case "number":
				if (!isFinite(variable))
					throw Error("invalid number: " + variable);
			case "boolean":
				return variable.toString();
			case "object":
				// return cached result if already processed
				if (cache.has(variable))
					return cache.get(variable);
				let result;
				if (Array.isArray(variable)){
					if (variable.length === 0 && !bAllowEmpty)
						throw Error("empty array in "+JSON.stringify(obj));
					result = '[' + variable.map(stringify).join(',') + ']';
				}
				else{
					var keys = Object.keys(variable).sort();
					if (keys.length === 0 && !bAllowEmpty)
						throw Error("empty object in "+JSON.stringify(obj));
```
