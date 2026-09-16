### Title
Missing `return` after private-payment hash failure causes duplicate async callback invocation and process crash - ([File: network.js])

### Summary
`network.js`'s `handleSavedPrivatePayments()` computes a payload hash for an attacker-supplied private-payment element with `objectHash.getBase64Hash()`. When this throws (which a crafted/malformed private-payment payload can trigger), the `catch` block already resolves the async item by calling `deleteHandledPrivateChain(..., cb)`, but execution then falls through to the code below the `try/catch` and unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain(...)` again, whose `ifOk`/`ifError` branches invoke `deleteHandledPrivateChain(..., cb)` a second time — double-invoking the `async.each` iteratee callback `cb` for the same item.

### Finding Description
In `network.js`, `handleSavedPrivatePayments()` iterates rows previously queued from `private_payments` device messages sent by a private-payment counterparty (an unprivileged peer, per `wallet.js` `handlePrivatePaymentChains` → `network.handleOnlinePrivatePayment` → `unhandled_private_payments` table). These payloads are only shallow-validated (`isNonemptyObject`/`isNonemptyArray` checks in `wallet.js:955-972`) before being persisted as raw JSON. [1](#0-0) 

When later re-processed, `validateAndSave` computes:
```js
try {
    var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
}
catch (e) {
    ...
    deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
}
var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, { ifOk: ..., ifError: ... });
``` [2](#0-1) 

`getBase64Hash` internally calls `getJsonSourceString`/`getSourceString`, both of which throw on values that are perfectly valid JSON but not accepted by the source-string serializer — e.g. an empty array/object, `NaN`/`Infinity`-producing numeric fields, `undefined`, or a string containing the internal join character — none of which are rejected by the shallow checks performed when the private-payment message was first accepted. [3](#0-2) [4](#0-3) 

Because there is no `return` statement after the `catch` block, the code always continues on to build `key` (using the now-`undefined` `json_payload_hash`) and to call `privatePayment.validateAndSavePrivatePaymentChain` again on the same element — even though the item was already finalized (and `cb` already called) inside the `catch` handler. `validateAndSavePrivatePaymentChain`'s `ifOk`/`ifError` callbacks each call `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` again, invoking the same `async.each` per-item callback `cb` a second time for the same row. [5](#0-4) 

Modern `async` library iteratee callbacks are wrapped with an "only-once" guard; calling them more than once throws `Error("Callback was already called...")`. This is an uncaught synchronous throw inside a database callback with no surrounding `try/catch`, so it propagates to the process-level `uncaughtException` handler, which explicitly re-throws to terminate the process: [6](#0-5) 

### Impact Explanation
Any full-node peer that has previously received a private payment (which is normal operation for anyone participating in private-asset transfers) can be crashed by a counterparty sending it a crafted `private_payments` device message whose payload causes `getBase64Hash`/`getJsonSourceString` to throw (e.g., an empty `outputs`/`inputs` sub-object, a numeric field serialized to `NaN`, or similar edge-case value not rejected by the initial shallow structural checks). The crash occurs asynchronously on a background retry pass (`handleSavedPrivatePayments`), so the attacker does not even need the victim to be online at the exact moment — the malformed data sits in `unhandled_private_payments` until reprocessed. This matches the CWE-502/CWE-770 pattern from the reference advisory: crafted structured input to a normally-reachable endpoint (here, the private-payment message handler) leads to an unhandled resource/serialization error that crashes the service — "a network unable to confirm new units" for the affected node, since the process is torn down and must be manually restarted.

### Likelihood Explanation
Reaching this requires only sending a `private_payments` message (over the existing hub-relay device-messaging channel used for legitimate private-payment delivery) with a payload element whose `payload` triggers a serialization error in `getSourceString`/`getJsonSourceString`. The upstream checks in `wallet.js:955-972` and `network.js:handleOnlinePrivatePayment` verify only that certain fields are non-empty objects/arrays/strings — they do not validate that every nested value is finite-number/non-empty-array/non-empty-object as required by the hashing routines. Crafting such a payload is straightforward for any wallet peer capable of initiating a private-asset send, making this a low-effort, high-impact DoS against any node that processes private payments.

### Recommendation
Add a `return` immediately after the `deleteHandledPrivateChain(...)` call inside the `catch` block in `handleSavedPrivatePayments()` (network.js) so the fallthrough path is never executed once the item has already been finalized. Additionally, harden the initial acceptance checks in `wallet.js:handlePrivatePaymentChains` (and `network.js:handleOnlinePrivatePayment`) to deep-validate private-payment payload fields (finite/positive amounts, non-empty nested arrays/objects, well-formed strings) before persisting them to `unhandled_private_payments`, so malformed data can never reach `getBase64Hash`/`getJsonSourceString` unguarded later. As defense in depth, wrap the whole `validateAndSave` body in try/catch to guarantee `cb` is invoked exactly once regardless of unexpected throws.

### Proof of Concept
1. Node B is paired with Node A and has previously exchanged/received private-asset payments (private-payment flow enabled).
2. Node B (attacker) sends Node A a `private_payments` device message via the hub with `body.chains = [[ { unit: "<64-char base64>", message_index: 0, payload: { asset: "<64-char base64>", denomination: 1, inputs: [{type:"issue", serial_number: 1, amount: 100}], outputs: [{}] }, output_index: 0, output: {...} } ]]` where an `outputs` element or nested field is crafted to be an empty object/array or contain a non-finite number, passing the shallow `isNonemptyObject`/`isNonemptyArray` checks in `handlePrivatePaymentChains` but causing `getSourceString`/`getJsonSourceString` to throw (`"empty object in ..."`, `"invalid number: ..."`, etc.) when later hashed.
3. The malformed chain is queued into `unhandled_private_payments` (via `savePrivatePayment`/`ifQueued` path when the referencing unit isn't yet known, or on retry).
4. When `network.handleSavedPrivatePayments()` next processes this row, `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` throws; the `catch` block calls `deleteHandledPrivateChain(..., cb)`, but execution falls through and calls `privatePayment.validateAndSavePrivatePaymentChain(...)` again, whose completion callback calls `deleteHandledPrivateChain(..., cb)` a second time.
5. `async.each`'s per-item callback (`cb`) is invoked twice for the same row, triggering `Error("Callback was already called")` from the `async` library, which propagates as an uncaught exception into `network.js`'s global `uncaughtException` handler, which re-throws and terminates the Node A process.

### Citations

**File:** network.js (L2461-2503)
```javascript
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

**File:** string_utils.js (L11-55)
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
				break;
			case "number":
				if (!isFinite(variable))
					throw Error("invalid number: " + variable);
				arrComponents.push("n", variable.toString());
				break;
			case "boolean":
				arrComponents.push("b", variable.toString());
				break;
			case "object":
				if (Array.isArray(variable)){
					if (variable.length === 0)
						throw Error("empty array in "+JSON.stringify(obj));
					arrComponents.push('[');
					for (var i=0; i<variable.length; i++)
						extractComponents(variable[i]);
					arrComponents.push(']');
				}
				else{
					var keys = Object.keys(variable).sort();
					if (keys.length === 0)
						throw Error("empty object in "+JSON.stringify(obj));
					keys.forEach(function(key){
						if (typeof variable[key] === "undefined")
							throw Error("undefined at "+key+" of "+JSON.stringify(obj));
						if (key.includes(STRING_JOIN_CHAR))
							throw Error("00 byte in object key in " + JSON.stringify(obj));
						arrComponents.push(key);
						extractComponents(variable[key]);
					});
				}
				break;
			default:
				throw Error("getSourceString: unknown type="+(typeof variable)+" of "+variable+", object: "+JSON.stringify(obj));
		}
```

**File:** string_utils.js (L220-253)
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
					result = '{' + keys.map(function(key){ return toWellFormedJsonStringify(key)+':'+stringify(variable[key]) }).join(',') + '}';
				}
				cache.set(variable, result);  // memoize for future references
				return result;
			default:
				throw Error("getJsonSourceString: unknown type="+(typeof variable)+" of "+variable+", object: "+JSON.stringify(obj));
		}
```
