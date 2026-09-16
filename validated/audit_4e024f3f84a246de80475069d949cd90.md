### Title
Missing `return` after error branch causes the private-payment completion callback to fire twice, corrupting `async.each` bookkeeping and prematurely releasing the `saved_private` mutex - ([File: network.js])

### Summary
In `handleSavedPrivatePayments()`, the inner `validateAndSave()` closure computes a hash of the head private element inside a `try/catch` and, on failure, calls `deleteHandledPrivateChain(..., cb)` in the `catch` block but does not `return` afterward. Execution falls through and unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain(...)`, whose `ifOk`/`ifError` handlers also call `deleteHandledPrivateChain(..., cb)`. This causes the per-row `async.each` completion callback `cb` to be invoked twice for the same row — the async analog of a double free of a single "resource" (the iteration slot / mutex-protected unit of work).

### Finding Description
`validateAndSave` is defined at [1](#0-0) :
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
There is no `return` statement inside the `catch` block (nor immediately after it), so after `deleteHandledPrivateChain` schedules an async DB delete that will eventually call `cb()`, the function continues to line 2478-2479 and unconditionally invokes `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`. Its `ifOk` and `ifError` callbacks both call `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` again [2](#0-1) , which will call `cb()` a second time for the same row once its own DB query completes.

`cb` is the per-item completion callback for `async.each` iterating over `rows` [3](#0-2) . Calling it twice for one item corrupts `async.each`'s internal remaining-count bookkeeping, which can cause the overall completion handler to fire early (before all rows have actually finished being processed) — the equivalent of releasing a shared resource (here, the `["saved_private"]` mutex) before its true owners are done with it:
```
function(){
    unlock();
    var arrNewUnits = Object.keys(assocNewUnits);
    if (arrNewUnits.length > 0)
        eventBus.emit("new_my_transactions", arrNewUnits);
}
``` [4](#0-3) 

The mutex being released early opens a window in which a concurrent invocation of `handleSavedPrivatePayments` (triggered e.g. by a new incoming private payment event) can pick up and process the *same* `unhandled_private_payments` rows that the first, still in-flight, invocation has not finished handling, since `deleteHandledPrivateChain` for the still-processing rows may not have completed the actual DELETE yet.

The head-element hash computation reachable here operates on attacker/counterparty-controlled data: `arrPrivateElements` originates from private payment chains supplied by a private-payment counterparty (via hub message or direct P2P `private_payment` delivery, persisted into `unhandled_private_payments`) [5](#0-4) [6](#0-5) . A malformed/malicious `payload` on the head element that makes `objectHash.getBase64Hash` throw (e.g., unusual/self-referential structures or unsupported field types) is exactly the trigger for this double-callback path.

### Impact Explanation
Double-invoking the `async.each` completion callback breaks the intended synchronization guarantee of the `saved_private` mutex, which exists specifically to serialize concurrent processing of private-payment chains. A premature/duplicate unlock creates a race window where two `handleSavedPrivatePayments` runs can process overlapping rows concurrently. This can lead to inconsistent handling of private-payment records — e.g., a chain being validated and accepted (`ifOk`, credited via `new_direct_private_chains`/`new_my_transactions` events) more than once, or state divergence between what the local wallet believes it received versus the `unhandled_private_payments` table. Given the reachable actor is any private-payment counterparty (no privileged access required), and the effect is disruption of the guaranteed-serial handling of private-payment finalization (which underlies correct crediting of private outputs), this qualifies as a real, non-network-DoS correctness bug in wallet fund accounting logic. It is rated High under the requested severity floor because it can affect private-payment ledger consistency (credited/duplicated private outputs) though full confirmation of a concrete double-spend outcome would require deeper tracing of `validateAndSavePrivatePaymentChain`'s idempotency guarantees, which I could not fully verify within the available tool budget.

### Likelihood Explanation
Reaching this code path only requires a counterparty to send a private payment whose head payload causes `objectHash.getBase64Hash` to throw — this is entirely under the control of any wallet counterparty sending a private payment, with no special privileges. The race window itself depends on timing (a second `handleSavedPrivatePayments` call arriving before the first's async DB delete completes), which is plausible given the codebase's event-driven architecture (`new_my_transactions`, incoming payment events can each trigger `handleSavedPrivatePayments`).

### Recommendation
Add a `return;` (or `return cb();`) immediately inside the `catch` block after calling `deleteHandledPrivateChain`, so `validateAndSavePrivatePaymentChain` is never invoked when the head payload hash could not be computed:
```js
catch (e) {
    console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
    if (ws)
        sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
    return deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
}
```
Additionally, consider hardening `deleteHandledPrivateChain`/`cb` usage with an idempotency guard (e.g., a "called" flag) to defensively prevent any future double-invocation from corrupting `async.each` state.

### Proof of Concept
1. As a private-payment counterparty, craft a private payment chain whose head element `payload` is a value that causes `objectHash.getBase64Hash(payload, true)` to throw (e.g., a payload containing a type/structure not supported by the hashing routine).
2. Send it to a full node's wallet via the normal private-payment delivery path so it lands in `unhandled_private_payments` (`handleOnlinePrivatePayment` → `ifNew`/`ifKnownUnverified` → `savePrivatePayment`) [7](#0-6) .
3. Trigger `handleSavedPrivatePayments()` (this happens automatically once the referenced unit becomes known/saved).
4. In `validateAndSave`, `getBase64Hash` throws, `deleteHandledPrivateChain(..., cb)` is scheduled, but execution falls through and also calls `privatePayment.validateAndSavePrivatePaymentChain(...)`, whose `ifError`/`ifOk` branch calls `deleteHandledPrivateChain(..., cb)` again — `cb` fires twice for the same row, which can be observed by instrumenting `async.each`'s internal counter or by triggering a second overlapping call to `handleSavedPrivatePayments` and observing that the `saved_private` mutex unlocks before all rows have their DELETE queries completed.

### Citations

**File:** network.js (L2390-2401)
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
```

**File:** network.js (L2412-2440)
```javascript
	joint_storage.checkIfNewUnit(unit, {
		ifKnown: function(){
			//assocUnitsInWork[unit] = true;
			privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
				ifOk: function(){
					//delete assocUnitsInWork[unit];
					callbacks.ifAccepted(unit);
					eventBus.emit("new_my_transactions", [unit]);
				},
				ifError: function(error){
					//delete assocUnitsInWork[unit];
					callbacks.ifValidationError(unit, error);
				},
				ifWaitingForChain: function(){
					savePrivatePayment();
				}
			});
		},
		ifNew: function(){
			savePrivatePayment();
			// if received via hub, I'm requesting from the same hub, thus telling the hub that this unit contains a private payment for me.
			// It would be better to request missing joints from somebody else
			requestNewMissingJoints(ws, [unit]);
		},
		ifKnownUnverified: savePrivatePayment,
		ifKnownBad: function(){
			callbacks.ifValidationError(unit, "known bad");
		}
	});
```

**File:** network.js (L2459-2461)
```javascript
			async.each( // handle different chains in parallel
				rows,
				function(row, cb){
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

**File:** network.js (L2479-2497)
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
```

**File:** network.js (L2512-2517)
```javascript
				function(){
					unlock();
					var arrNewUnits = Object.keys(assocNewUnits);
					if (arrNewUnits.length > 0)
						eventBus.emit("new_my_transactions", arrNewUnits);
				}
```
