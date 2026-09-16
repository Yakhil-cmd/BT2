### Title
Missing `return` after error handling causes use of uninitialized variable and duplicate callback invocation in private-payment retry flow - (File: network.js)

### Summary
In `handleSavedPrivatePayments()` → `validateAndSave()` (`network.js`), a `try/catch` around `objectHash.getBase64Hash()` fails to `return` after handling the exception, mirroring the mlx5e bug class: an error branch is taken, cleanup is performed, but execution falls through and continues using data that was never (successfully) initialized, and re-invokes the completion callback a second time.

### Finding Description
`getBase64Hash()` is called to compute a validation key from an attacker/counterparty-supplied private-payment payload: [1](#0-0) 

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

`deleteHandledPrivateChain(..., cb)` is called inside the `catch` block, which itself invokes `cb` (the `async.each` iteratee callback) once it finishes deleting the row (see the surrounding `async.each` over `unhandled_private_payments` rows, `network.js:2459-2518`). Because there is no `return` after this call, execution **continues past the catch block** in the same tick:

1. `json_payload_hash` remains `undefined` (its `var` was declared inside the failed `try`), so `key` is built as `"private_payment_validated-<unit>-undefined-<output_index>"` — an uninitialized value used exactly as in the reference CVE, where `zone_rule->attr` was used despite the failing branch.
2. `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` is invoked a **second time** on the same, already-known-malformed payload, with `ifOk`/`ifError`/`ifWaitingForChain` callbacks that themselves call `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` or `cb()` again.

This results in `cb` (the `async.each` iteratee completion callback) being invoked twice for the same row.

### Impact Explanation
`getBase64Hash` calls `getJsonSourceString`, which recursively serializes the (attacker-influenced) `payload` object; a private-payment counterparty (or any wallet peer sending a `private_payments` message that later gets queued and retried through `handleSavedPrivatePayments`, e.g. via `ifQueued`/`savePrivatePayment` in `handleOnlinePrivatePayment`) can supply a payload structured to throw during hashing (e.g., pathological/oversized/self-referential nested structures reaching stack or serialization limits), or the JSON round-trip through `unhandled_private_payments` can otherwise cause `getBase64Hash` to throw. Once thrown, `async`'s iteratee `cb` is called twice for the same item, which the `async` library treats as an error ("Callback was already called") and throws synchronously, unhandled, crashing the Node.js process. Because `handleSavedPrivatePayments` runs whenever private payments are received/retried, a single malformed private payment sent by a payment counterparty can reliably crash the recipient's wallet/hub process — a remotely triggerable denial-of-service that stops the node from processing and confirming any further units, matching the "network unable to confirm new units" acceptance criterion.

### Likelihood Explanation
The `validateAndSave` function is reached automatically for any private payment chain stored via `handleOnlinePrivatePayment` (`network.js:2412-2440`) when the head element cannot be validated immediately (`ifKnownUnverified`/`ifNew` → `savePrivatePayment`) and is later reprocessed by `handleSavedPrivatePayments`. The payload originates from data sent over the wire by a private-payment counterparty and is only loosely validated by `wallet.js`'s `handlePrivatePaymentChains` (non-empty object/array/string field checks; no deep-structure or serialization-safety validation), so a counterparty fully controls the shape of `payload` fed into `getBase64Hash`. No special privileges beyond being a private-payment counterparty/device sending a payment/notification are required.

### Recommendation
Add an explicit `return` inside the `catch` block so execution does not fall through to use `json_payload_hash` or re-invoke `cb`/`validateAndSavePrivatePaymentChain`:
```js
catch (e) {
    console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
    if (ws)
        sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
    return deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
}
```
Additionally, guard `getJsonSourceString`/`getBase64Hash` against pathological inputs (depth/size limits) so a single malformed payload cannot throw deep in serialization, and audit other call sites that call an async completion inside a `catch` without a subsequent `return` for the same fall-through hazard.

### Proof of Concept
1. As a private-payment counterparty/device, send (or cause to be queued, e.g. via a delayed/`ifKnownUnverified` path) a `private_payments` message whose head element's `payload` is crafted so that `getJsonSourceString`/`JSON.stringify`-based serialization throws (e.g., an extremely deeply nested or otherwise pathological object structure that passes the shallow checks in `wallet.js handlePrivatePaymentChains`, i.e. is a non-empty object/array with the required string/array fields but nested to a depth/size that triggers a serialization exception).
2. The payment is stored to `unhandled_private_payments` and later reprocessed by `handleSavedPrivatePayments`.
3. In `validateAndSave`, `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` throws; the `catch` block calls `deleteHandledPrivateChain(..., cb)` (invoking `cb` once) but does not return.
4. Execution falls through, computing `key` with `undefined` hash and calling `privatePayment.validateAndSavePrivatePaymentChain(...)` again, whose `ifError`/`ifOk` handler calls `cb` a second time.
5. `async.each`'s double-callback detection throws synchronously, crashing the node process — denial of service, preventing the node from confirming any further units until manually restarted.

### Citations

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
