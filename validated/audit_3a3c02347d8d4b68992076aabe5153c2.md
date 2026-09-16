### Title
Missing `return` after caught hash exception leads to double async-callback invocation / crash in private payment processing - ([File: network.js])

### Summary
`handleSavedPrivatePayments()` in `network.js` computes a hash of an attacker-controlled private-payment payload inside a `try/catch`, but the `catch` block does not `return` after handling the error. Execution falls through and unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain()` with the same `async.each` iteratee callback `cb` that was already invoked from inside the `catch` block, resulting in a double callback invocation. This mirrors the OpenSIPS `calc_tag_suffix`/`MD5StringArray` bug class: a value that fails to be safely processed (there: uninitialized string passed to hashing, causing a segfault; here: an unhashable payload causing an exception) is not properly aborted on, and the code continues to operate on corrupted/undefined state, crashing the process.

### Finding Description
`handleOnlinePrivatePayment()` (network.js, `savePrivatePayment`) stores an arbitrary, mostly-unvalidated `payload` object sent by a peer (or forwarded via a hub, or a paired device) into the `unhandled_private_payments` table: [1](#0-0) 
Only `unit`, `message_index`, and `output_index` are format-checked before this JSON is persisted: [2](#0-1) 

Later, `handleSavedPrivatePayments()` re-reads this JSON and computes a hash of the head element's `payload`: [3](#0-2) 

`objectHash.getBase64Hash(..., true)` calls `getJsonSourceString`, which throws `Error` for values such as empty arrays/objects, non-finite numbers, or unsupported types: [4](#0-3) 

When that throw happens, the `catch` block logs the error, optionally sends a result to the peer, and calls `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` — invoking the `async.each` callback `cb` once. But there is no `return` statement, so execution falls through to line 2478-2479 and unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`, whose `ifOk`/`ifError`/`ifWaitingForChain` handlers each also eventually call `cb()` (via `deleteHandledPrivateChain(...)` or directly): [5](#0-4) 

Calling an `async.each` iteratee callback more than once is undefined behavior in the `async` library, and typically throws an uncaught exception ("Callback was already called") that crashes the Node.js process, or otherwise corrupts the mutex/iteration state (`unlock()` being reached with stale bookkeeping, `assocNewUnits` mutated after `unlock()`, etc.), matching the "Denial of Service due to a crash" impact of the referenced CVE.

### Impact Explanation
A crash or corrupted async control flow in a core network/wallet processing path (`handleSavedPrivatePayments`) is a Denial of Service condition, taking down the node/wallet process handling private payments — analogous to the segfault DoS in the OpenSIPS advisory. This function runs unconditionally whenever any private payment is queued (`setInterval`/event-driven), so a single malformed private-payment message from an unprivileged sender can repeatedly retrigger the crash for any node/wallet/hub-connected client that stores the malformed chain.

### Likelihood Explanation
Any unprivileged peer or paired device can send a `private_payment` message with a `payload` engineered to make `getJsonSourceString`/`getSourceString` throw (e.g., an outputs/inputs array structured so the head element's `payload` ends up an empty object/array after JSON round-trip, or containing a value type unsupported by the hashing routine). The message passes the shallow checks in `handleOnlinePrivatePayment` (only `unit`/`message_index`/`output_index` format is checked) and is persisted, guaranteeing the vulnerable code path executes on the next call to `handleSavedPrivatePayments`.

### Recommendation
Add a `return` (or restructure with an early return/guard) inside the `catch` block at network.js line 2472-2477 so execution does not continue to line 2478-2479 after an error has already been handled and `cb` already invoked. Ensure the async callback is invoked exactly once per iteration.

### Proof of Concept
1. As an unprivileged peer/paired device, send a `private_payment` justsaying/message whose `arrPrivateElements[0].payload` is well-formed enough to pass the checks in `handleOnlinePrivatePayment` (valid `unit`, `message_index`, `output_index`) but causes `getJsonSourceString` to throw when hashed (e.g., an `outputs`/`inputs` array or nested object that normalizes to an empty array/object, or a numeric field set to `Infinity`/`NaN` via a crafted large exponent that survives JSON parsing as `Infinity`).
2. The payload is stored via `savePrivatePayment` into `unhandled_private_payments`.
3. When `handleSavedPrivatePayments()` runs, `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` throws; the `catch` block calls `deleteHandledPrivateChain(..., cb)` (invoking `cb` once) but execution falls through and calls `privatePayment.validateAndSavePrivatePaymentChain(...)`, whose completion handlers invoke `cb` a second time — triggering the `async` library's "Callback was already called" exception and crashing the process (or leaving the `["saved_private"]` mutex/lifecycle in a corrupted state).

### Citations

**File:** network.js (L2376-2389)
```javascript
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
	if (!ValidationUtils.isValidBase64(unit, constants.HASH_LENGTH))
		return callbacks.ifError("invalid unit");
	if (!ValidationUtils.isNonnegativeInteger(message_index))
		return callbacks.ifError("invalid message_index");
	if (!(ValidationUtils.isNonnegativeInteger(output_index) || output_index === -1))
		return callbacks.ifError("invalid output_index");

```

**File:** network.js (L2390-2402)
```javascript
	var savePrivatePayment = function(cb){
		// we may receive the same unit and message index but different output indexes if recipient and cosigner are on the same device.
		// in this case, we also receive the same (unit, message_index, output_index) twice - as cosigner and as recipient.  That's why IGNORE.
		db.query(
			"INSERT "+db.getIgnore()+" INTO unhandled_private_payments (unit, message_index, output_index, json, peer) VALUES (?,?,?,?,?)", 
			[unit, message_index, output_index, JSON.stringify(arrPrivateElements), bViaHub ? '' : ws.peer], // forget peer if received via hub
			function(){
				callbacks.ifQueued();
				if (cb)
					cb();
			}
		);
	};
```

**File:** network.js (L2467-2478)
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
```

**File:** network.js (L2479-2503)
```javascript
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
