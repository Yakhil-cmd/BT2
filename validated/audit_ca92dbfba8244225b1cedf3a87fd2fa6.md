### Title
Missing `return` after hash-failure causes double-processing of unhandled private payments - (File: `network.js`)

### Summary
In `handleSavedPrivatePayments()`, the `validateAndSave` inner function computes `json_payload_hash` from the incoming private-payment head element and, on failure, is supposed to abort processing of that row. Instead, execution falls through and the same `arrPrivateElements` is passed to `privatePayment.validateAndSavePrivatePaymentChain(...)` anyway, invoking the `async.each` iteration callback (`cb`) twice for the same row. This mirrors the CVE-2024-58075 bug class: "do not transfer/continue processing when the init/hash step fails."

### Finding Description
`handleSavedPrivatePayments()` reads rows from `unhandled_private_payments` and, for each one, calls `validateAndSave`: [1](#0-0) 

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
    privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, { ... });
};
```

When `objectHash.getBase64Hash()` throws (e.g., because the stored/attacker-controlled `payload` JSON contains a value type that the hashing routine cannot serialize/hash — the same class of malformed private-payment payload that other call sites explicitly guard against), the `catch` block calls `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` — which itself invokes `cb()` (the `async.each` per-item completion callback) once the DB delete finishes — but there is **no `return`** after this call. Execution therefore falls through to compute `key` (with `json_payload_hash === undefined`) and call `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` on the very same, already-failed `arrPrivateElements`.

That second call will eventually invoke one of `ifOk`, `ifError`, or `ifWaitingForChain`, each of which calls `deleteHandledPrivateChain(...)` (or `cb()` directly for `ifWaitingForChain`) a second time — i.e., the `async.each` iterator callback `cb` for that row gets invoked twice.

Contrast this with the correct pattern used elsewhere in the same codebase, where the equivalent hash-failure path properly `return`s before continuing: [2](#0-1) 

This is the exact bug class described in the CVE: an init/pre-check step (`tegra_cmac_init`/`tegra_sha_init` in the kernel; `getBase64Hash` here) can fail, and the failure is not used to stop the subsequent transfer/processing step, so the same request/data continues to be transferred/processed after already being handed off for cleanup.

### Impact Explanation
`async.each` is not designed to tolerate its per-item callback being called more than once for the same item; the double callback can:
- cause `async.each`'s internal completion counter to under/overshoot, triggering the final callback (`unlock()` on the `"saved_private"` mutex) prematurely while other rows in the batch are still being validated/saved, or triggering it multiple times,
- allow a second, concurrent `validateAndSavePrivatePaymentChain` on the same row to race with DB writes from a first attempt, since one branch already issued `DELETE FROM unhandled_private_payments` while the other branch continues to write to `outputs`/`inputs` for that same unit/message/output.

Because `handleSavedPrivatePayments` is the entry point that finalizes and writes disclosed private-payment chains (spend inputs and outputs) for privately-transferred assets, corrupting its completion/lock semantics can lead to inconsistent processing of a private asset transfer — the general class of impact this scan is required to look for is "unauthorized spending" / "node disagreement on validity" for private-payment paths reachable by a private-payment counterparty who controls the `payload` of a private element sent to the victim wallet.

### Likelihood Explanation
Any peer/private-payment counterparty who can get a private-payment chain queued into `unhandled_private_payments` (via `handleOnlinePrivatePayment`, reachable from `handlePrivatePaymentChains`/wallet network handlers for private payments) controls the head element's `payload`. If that payload can be crafted so that `objectHash.getBase64Hash()` throws (the same category of malformed payload that necessitates the `try/catch` in the first place, and which other call sites treat as a hard validation failure), the buggy fallthrough is triggered deterministically. No special privileges beyond being a private-payment counterparty are required.

### Recommendation
Add a `return` statement after the `deleteHandledPrivateChain(...)` call inside the `catch` block in `validateAndSave` (network.js), matching the pattern already used in `handlePrivatePaymentChains` (wallet.js), so that a hash-computation failure aborts processing of that row instead of falling through to `privatePayment.validateAndSavePrivatePaymentChain`.

### Proof of Concept
1. As a private-payment counterparty, send a private-payment chain (`private_payment` / `private_payment_chains` message) whose head element's `payload` is structured so that `objectHash.getBase64Hash(payload, true)` throws (e.g., a payload field type unsupported by the hashing/serialization routine used by `object_hash.js`, analogous to the malformed-payload cases guarded elsewhere).
2. The message is queued into `unhandled_private_payments` (via `handleOnlinePrivatePayment`'s `ifQueued`/`ifNew` paths).
3. `handleSavedPrivatePayments()` picks up the row and calls `validateAndSave`; `getBase64Hash` throws, the `catch` block sends an error result and calls `deleteHandledPrivateChain(..., cb)`.
4. Execution falls through (no `return`) and immediately calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` on the same, already-errored element, resulting in a second invocation of `cb` for that `async.each` item once one of `ifOk`/`ifError`/`ifWaitingForChain` fires — observable as duplicate `deleteHandledPrivateChain` DB deletes/duplicate log lines and (depending on timing) `unlock()` on the `"saved_private"` mutex firing while sibling rows in the same batch are still in flight.

Note: I was unable to fully inspect `object_hash.js`'s `getBase64Hash`/`getSourceString` implementation to enumerate every concrete payload shape that triggers the throw (index size/content limits truncated that lookup). Confirming the exact malformed-payload trigger would require a Devin session with full file access.

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

**File:** wallet.js (L1027-1032)
```javascript
			try {
				var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
			}
			catch (e) {
				return cb("head priv element hash failed " + e.toString());
			}
```
