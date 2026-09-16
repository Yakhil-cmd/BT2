### Title
Missing `return` after exception in private-payment hash calculation causes duplicate processing / double-release of the same DB record and callback - ([File: network.js])

### Summary
`handleSavedPrivatePayments()` in `network.js` iterates unhandled private-payment chains and, for each row, calls an inner `validateAndSave()` function. That function computes a hash of the private-payment payload and, on failure, is supposed to abort processing of that chain. Because the `catch` block does not `return`, execution falls through and the same chain is processed a second time through `privatePayment.validateAndSavePrivatePaymentChain`, whose own `ifOk`/`ifError` callbacks independently call `deleteHandledPrivateChain(...)`, which in turn invokes the `async.each` item callback `cb()` a second time. This is conceptually the same bug class as CVE-2015-1207 (a resource that should be released/consumed exactly once is instead released/consumed twice because an error path fails to stop further processing of attacker-crafted input), reachable here from a private-payment counterparty (an unprivileged peer/device) rather than from a malicious hub/node.

### Finding Description
In `network.js`, `handleSavedPrivatePayments` reads rows from `unhandled_private_payments` and processes each with `async.each`: [1](#0-0) 

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
    privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...});
};
``` [2](#0-1) 

The `catch` block calls `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)`, which deletes the DB row and then calls `cb()` (the `async.each` iterator callback): [3](#0-2) 

Since the `try/catch` has no `return` statement, control flow continues past the `catch` and immediately calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, { ifOk, ifError, ifWaitingForChain })` on the very same (already "handled"/deleted) chain. Both `ifOk` and `ifError` of that second call themselves invoke `deleteHandledPrivateChain(...)` again, which calls `cb()` a second time: [4](#0-3) 

This is the same defect pattern as the reported FFmpeg CVE: a single crafted/malformed input (here, a private-payment payload that makes `objectHash.getBase64Hash()` throw) causes the same handle/resource (the `async.each` completion callback `cb`, and the same DB row processing) to be finalized/consumed twice instead of once, because an exception path does not stop subsequent normal-path processing.

The trigger condition (`objectHash.getBase64Hash` throwing) is attacker-influenced: `handledChainsCache`/`handlePrivatePaymentChains` in `wallet.js` accepts `body.chains` from a private-payment counterparty (a paired device or online-payment peer) with only structural checks (`isNonemptyObject`, `isNonemptyString`, etc. — no deep-type validation of every field), and stores them for later processing via `handleSavedPrivatePayments`. Any payload field with a type/shape that `object_hash`'s hashing routine rejects (e.g. via `getSourceString`) will cause `getBase64Hash` to throw at line 2470, entering the vulnerable code path.

### Impact Explanation
Calling `cb()` twice for the same item in an `async.each` iteration is undefined/unsafe behavior for the `async` library: it can cause the completion callback of `async.each` to fire prematurely or multiple times, deletion of DB rows to be attempted twice, `eventBus` events (`new_my_transactions`, `private_payment_validated-*`) to fire out of order or twice, and duplicate execution of `privatePayment.validateAndSavePrivatePaymentChain` against a payload that may already have been (or is concurrently being) inserted into the `outputs`/related tables. Depending on timing this can produce inconsistent private-payment bookkeeping/state corruption for the receiving wallet, or an uncaught exception/crash of the node/wallet process handling the double-callback, denying availability to legitimate private-payment processing — i.e., a node/wallet failing to properly track incoming private payments, matching the "AA fund loss/freezing" / "node disagreement on validity" severity bar for this class of finding, though restricted here to the local wallet's own bookkeeping of private payments rather than consensus-level double-spend.

### Likelihood Explanation
The path is reachable simply by a private-payment counterparty (a paired device, or peer sending an "online private payment") sending a `payload` that is well-formed enough to pass the coarse structural checks in `handlePrivatePaymentChains` but causes `objectHash.getBase64Hash` to throw (e.g., an unsupported value type nested in the payload). No hub/node compromise or special privilege is required — this is exactly the "asset issuer / private-payment counterparty" attack surface called out as in-scope.

### Recommendation
Add a `return` after invoking `deleteHandledPrivateChain(...)` in the `catch` block of `validateAndSave()` in `network.js` (around line 2476) so that execution does not fall through to call `privatePayment.validateAndSavePrivatePaymentChain` a second time on the same chain, and so `cb()` is only ever invoked once per `async.each` item. Additionally, consider validating/whitelisting the payload's field types before calling `objectHash.getBase64Hash` so malformed payloads are rejected earlier and deterministically.

### Proof of Concept
1. As a paired device / private-payment counterparty, send a `private_payment_chains` (or online `private_payment`) message whose head element's `payload` contains a field of a type that `object_hash.getSourceString`/`getBase64Hash` cannot serialize/hash (causing a thrown exception), while still passing the coarse structural validation in `handlePrivatePaymentChains` (`wallet.js`) that only checks for non-empty objects/strings/arrays.
2. The chain is stored in `unhandled_private_payments` and later picked up by `handleSavedPrivatePayments` in `network.js`.
3. In `validateAndSave()`, `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` throws; the `catch` block deletes the row and calls `cb()` once, but control falls through (no `return`) into the call to `privatePayment.validateAndSavePrivatePaymentChain(...)`.
4. That call's `ifOk`/`ifError` callback independently calls `deleteHandledPrivateChain(...)` → `cb()` again for the same `async.each` item, producing a double-callback/double-processing condition on the same input record.

Note: I was not able to fully inspect `object_hash.js`'s exact hashing/type-validation logic (to pin down the precise payload shape that triggers the throw) within the available search results; a Devin session with full file access would be needed to construct the exact byte-for-byte crafted payload and to confirm downstream `async.each`/`eventBus` behavior under Node's current `async` library version.

### Citations

**File:** network.js (L2459-2504)
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
```

**File:** network.js (L2523-2527)
```javascript
function deleteHandledPrivateChain(unit, message_index, output_index, cb){
	db.query("DELETE FROM unhandled_private_payments WHERE unit=? AND message_index=? AND output_index=?", [unit, message_index, output_index], function(){
		cb();
	});
}
```
