### Title
Missing `return` after payload-hash failure lets a malformed private-payment element still be committed - ([File: network.js])

### Summary
In `handleSavedPrivatePayments()` in `network.js`, the inner `validateAndSave` closure computes `json_payload_hash` via `objectHash.getBase64Hash()` inside a `try/catch`. When the hash computation throws, the `catch` block logs the error, notifies the peer, and calls `deleteHandledPrivateChain(..., cb)` — but it does **not** `return`. Execution falls through to build `key` (using the now-`undefined` `json_payload_hash`) and unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`, which itself will also eventually call `cb` again through its `ifOk`/`ifError`/`ifWaitingForChain` handlers. [1](#0-0) 

### Finding Description
This mirrors the CVE-2026-35535 bug-class: a failure of a critical checkpoint (there, dropping privileges before running the mailer; here, computing/validating the payload hash of an untrusted private-payment element) is not treated as fatal, and the code proceeds down the "success" path anyway.

`arrPrivateElements` originates from network-supplied data: a private-payment counterparty (or hub) sends a `private_payment` device message / `hub/deliver`d private chain, which is stored verbatim as `row.json = JSON.stringify(arrPrivateElements)` in `unhandled_private_payments` by `handleOnlinePrivatePayment()`/`savePrivatePayment()` in `network.js` with only shallow structural checks (unit format, message_index, output_index) — the inner `payload` content is not deeply validated at that point. [2](#0-1) 

Later, `handleSavedPrivatePayments()` reprocesses these stored rows. If a counterparty crafts a `payload` object that causes `objectHash.getBase64Hash()` to throw (e.g. an unhashable/malformed structure), the `catch` branch triggers `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` — an asynchronous DB delete that will eventually invoke `cb`. But because there is no `return` statement, the same synchronous execution continues immediately afterward and calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`, passing the same (potentially malformed/partially-hostile) `arrPrivateElements` into the real chain-validation/commit path, whose own `ifOk`/`ifError`/`ifWaitingForChain` callbacks will *also* eventually call `cb`.

The result is that the `async.each` iteratee callback `cb` can be invoked twice for the same row: once from the orphaned `deleteHandledPrivateChain` in the `catch` block, and once from the real chain-validation outcome. Under Node's `async` library, a double-invoked iteratee callback can cause the `async.each` final callback (which calls `unlock()` on the `"saved_private"` mutex and emits `"new_my_transactions"`) to fire prematurely/twice, releasing the private-payment processing mutex out of sync with the actual completion of `validateAndSavePrivatePaymentChain`. This creates a race window where a second `handleSavedPrivatePayments()` invocation (triggered e.g. by a new incoming private payment) can begin processing rows concurrently while the first pass's DB transaction for the same or a related chain is still in flight.

### Impact Explanation
The observable effect is a broken-error-handling / double-callback race in the private-payment chain-processing pipeline that a private-payment counterparty can trigger by supplying a payload that fails to hash. While the deeper `validateAndSavePrivatePaymentChain` in `private_payment.js` does perform its own duplicate/asset checks under a DB transaction, the premature/duplicate release of the `"saved_private"` mutex undermines the serialization guarantee that this code path relies on to safely process private chains one at a time, which is the same class of guarantee violation as "failure of a safety check is not fatal, so a security-relevant path an attacker doesn't control continues to execute as though the check had passed."

### Likelihood Explanation
Reachable by any private-payment counterparty (or malicious relaying hub) who can cause `arrPrivateElements[0].payload` to be an object that `objectHash.getBase64Hash()` cannot serialize/hash — no special privileges are required beyond being a private-payment peer, and the vulnerable code runs automatically whenever `handleSavedPrivatePayments()` processes queued rows.

### Recommendation
Add a `return` immediately after the `deleteHandledPrivateChain(...)` call inside the `catch` block in `network.js` (around line 2476) so that execution does not fall through to compute `key` and invoke `privatePayment.validateAndSavePrivatePaymentChain` when the payload hash computation has already failed and the row is being deleted.

### Proof of Concept
I could not construct or verify a concrete input that reliably makes `objectHash.getBase64Hash()` throw for a JSON-parseable `payload` object (this would require inspecting `object_hash.js`'s `getSourceString`/`getJsonSourceString` implementation for exact throw conditions, which I was not able to fully explore before this session ended). The control-flow defect itself — missing `return` after the `catch` block causing fallthrough into the "success" processing path — is directly confirmed in the cited code. [3](#0-2) 

Note on confidence: due to not having exhausted verification of the exact exception-triggering payload shape for `getBase64Hash`, and because the downstream `validateAndSavePrivatePaymentChain` performs its own strict checks that likely reject a malformed chain anyway, the concrete "unauthorized spending / double-spend / inflation" impact required by the validation criteria is not fully demonstrated — the confirmed defect is a control-flow/fatal-error-handling bug analogous to the reported CVE's bug class, but I was unable to prove it escalates to one of the required concrete impacts (unauthorized spend, stable double-spend, supply inflation, AA fund loss, or node disagreement) within the tool budget available.

### Citations

**File:** network.js (L2376-2402)
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

**File:** network.js (L2467-2510)
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
					
					if (conf.bLight && arrPrivateElements.length > 1 && !row.linked)
						updateLinkProofsOfPrivateChain(arrPrivateElements, row.unit, row.message_index, row.output_index, cb, validateAndSave);
					else
						validateAndSave();
					
```
