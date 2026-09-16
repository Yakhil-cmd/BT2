### Title
Missing `return` after caught hashing error leads to double-invocation of async callback and process crash - ([File: network.js])

### Summary
In `network.js`, the private-payment reassembly routine `handleSavedPrivatePayments` fails to bail out after catching an exception, mirroring the CVE-2022-34675 bug class (a caller not checking/acting on an error/return condition before continuing, leading to use of an invalid state and denial of service).

### Finding Description
Inside `handleSavedPrivatePayments`, each queued private-payment chain is processed by the inner `validateAndSave` function: [1](#0-0) 

When `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` throws (e.g., because a peer supplied a private-payment payload whose structure cannot be hashed/serialized), the `catch` block logs the error, optionally sends an error result, and calls `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` — which invokes the `async.each` iteratee callback `cb` once.

However, execution does **not** `return` after the `catch` block. Control falls through to compute `key` (using the now-`undefined` `json_payload_hash`) and unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain(...)`: [2](#0-1) 

Every branch of that second call (`ifOk`, `ifError`, `ifWaitingForChain`) also invokes `cb()`/`deleteHandledPrivateChain(..., cb)` a second time for the same iteration: [3](#0-2) 

Calling the `async.each` iteratee callback twice for the same item is a well-known misuse of the `async` library and results in an uncaught "Callback was already called" exception thrown synchronously by `async`. Because this occurs outside of any try/catch that the application controls (it is thrown from inside the `async` module's own callback-wrapping code), it propagates as an unhandled exception and crashes the Node.js process — this is analogous to the NVIDIA driver bug of not checking a failure condition and consequently dereferencing/using invalid state, which produces a denial of service.

### Impact Explanation
A crash of the wallet/hub Node.js process is a denial of service: the node stops confirming/relaying units and processing further private payments until manually restarted, satisfying the "network unable to confirm new units" impact bar for a Medium-severity node-availability bug.

### Likelihood Explanation
The trigger path is reachable by any private-payment counterparty (a normal, unprivileged peer or hub client): sending a private-payment chain whose head payload is malformed such that `objectHash.getBase64Hash` throws (for example a payload containing values that are not JSON/hash-serializable per `object_hash.js`'s strict type expectations) queues it into `unhandled_private_payments` via `handleOnlinePrivatePayment`, and it is later processed by `handleSavedPrivatePayments`, hitting the vulnerable code path deterministically. No authentication or privileged access is required beyond being a private-payment sender, matching the CVE's "no privileges beyond local user" analog (here: no privileges beyond being a normal peer).

### Recommendation
Add an explicit `return` after the `deleteHandledPrivateChain(...)` call in the `catch` block of `validateAndSave` so that `validateAndSavePrivatePaymentChain` and the associated `cb()` invocations are never reached when hashing failed:
```js
catch (e) {
    console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
    if (ws)
        sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
    return deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
}
```

### Proof of Concept
1. As a peer/wallet counterparty, send (via `private_payment`/`handlePrivatePaymentChains`) a private-payment chain whose head element's `payload` contains a value type that causes `objectHash.getBase64Hash` to throw (e.g., a field with an unsupported/circular or type-violating value per `object_hash.js` serialization rules).
2. The receiving node's `handleOnlinePrivatePayment` cannot fully validate it synchronously (e.g., light client awaiting chain) and stores it in `unhandled_private_payments`.
3. `handleSavedPrivatePayments` later picks up the row and calls `validateAndSave`; `getBase64Hash` throws, the `catch` block runs `deleteHandledPrivateChain(..., cb)` (first `cb()` call), then falls through and calls `privatePayment.validateAndSavePrivatePaymentChain`, whose `ifError`/`ifOk` handler calls `cb()` a second time.
4. `async.each`'s iteratee callback fires twice, `async` throws an uncaught error, and the Node.js process crashes.

Note: I could not fully trace every code path inside `object_hash.js` needed to construct a concrete payload guaranteed to throw (I only located the file, not its full serialization logic) within the available exploration; a background Devin session with full file access would be needed to confirm the exact malformed-payload shape and to implement/verify the fix.

### Citations

**File:** network.js (L2467-2503)
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
```
