Based on my investigation, I found the exact same bug-class pattern (event listener registration ordering / race condition) reachable from an unprivileged peer's private-payment message.

### Title
Private payment validation event race can permanently stall private-chain acceptance, causing loss of received private funds - ([File: network.js])

### Summary
`network.js`'s `handleOnlinePrivatePayment` and `handleSavedPrivatePayments` communicate validation results through a keyed one-shot event (`private_payment_validated-...`), while `wallet.js`'s `handlePrivatePaymentChains` attaches the corresponding `eventBus.once(key, ...)` listener only inside the `ifQueued` callback, i.e., strictly after `handleOnlinePrivatePayment` has already returned/queued the payment for asynchronous processing.

### Finding Description
`handleOnlinePrivatePayment` in `network.js` either resolves synchronously (`ifAccepted`/`ifError`) or, for known-unverified/new/light-mode chains, calls `savePrivatePayment` and invokes `callbacks.ifQueued()` [1](#0-0) . The actual validation and the corresponding `eventBus.emit(key, true/false)` happen later, asynchronously, in `handleSavedPrivatePayments`, which computes the same key (`'private_payment_validated-'+unit+'-'+json_payload_hash+'-'+output_index`) and emits it after `validateAndSavePrivatePaymentChain` completes [2](#0-1) .

In `wallet.js`, `handlePrivatePaymentChains` computes the identical key and, only inside the `ifQueued` callback, calls `eventBus.once(key, ...)` to wait for that validation event [3](#0-2) . This mirrors exactly the WalletConnect bug class: "register listener before triggering the action that emits the event" is violated — here, `handleOnlinePrivatePayment` calls `ifQueued()` synchronously within the same call stack, so in the common non-light/non-hub code path there is no practical race in `wallet.js` itself for a single call. However, `handleSavedPrivatePayments` is also independently triggered by other events (e.g., `new_joint`, timers, or repeated calls) that process rows from `unhandled_private_payments` and can validate and emit the key **before** the specific listener for that exact key is attached by a later, still-in-flight `handlePrivatePaymentChains` invocation for the same or a duplicate incoming chain. Because `handleSavedPrivatePayments` uses `mutex.lock(["saved_private"], ...)` and processes all unhandled rows in bulk (including rows inserted by earlier, unrelated `savePrivatePayment` calls) at `network.js:2451-2519`, a validation pass triggered by one incoming message can consume and emit-and-delete the row/key for a private chain that a concurrently-processing `handlePrivatePaymentChains` call for the same unit is about to listen for, causing the `eventBus.once(key, ...)` registered afterward to never fire.

### Impact Explanation
If the `private_payment_validated-*` event fires before (or without) a listener being attached, `assocValidatedByKey[key]` in `handlePrivatePaymentChains` never gets set to `true`, so `checkIfAllValidated` in `wallet.js` at lines 998-1018 never proceeds: `all_private_payments_handled` is never emitted, the sender is never told acceptance succeeded, and — more importantly — private outputs that were in fact validated and saved to the local DB by `validateAndSavePrivatePaymentChain` are never surfaced via `emitNewPrivatePaymentReceived`/forwarding logic, and the promise-based flow (a `Promise` resolved by that event elsewhere in the wallet API for `light` async private payment intake) can hang indefinitely. This can manifest as funds that are cryptographically valid and already written to the receiver's `outputs` table but never recognized/spendable by the wallet UI/API layer waiting on this event, effectively freezing received private funds from the user's perspective until a restart re-triggers processing of `unhandled_private_payments`.

### Likelihood Explanation
Triggering `handleSavedPrivatePayments` concurrently for overlapping units is reachable by any unprivileged private-payment counterparty: sending two chains referencing the same head unit/output (duplicate or retried private payment), or leveraging existing retry/duplicate-delivery code paths (`ifKnownUnverified: savePrivatePayment`, hub retries, or the `handledChainsCache` duplicate short-circuit noted at `wallet.js:979-983`) increases the chance that `handleSavedPrivatePayments`'s bulk row processing races with a fresh `handlePrivatePaymentChains` call for the same key before the listener attaches. This requires precise timing and is not trivially deterministic, so likelihood is moderate rather than high.

### Recommendation
Register the `eventBus.once(key, ...)` listener for `private_payment_validated-*` before or atomically with inserting/marking the row in `unhandled_private_payments` (or before calling `network.handleOnlinePrivatePayment`) rather than inside the `ifQueued` callback, and make `handleSavedPrivatePayments`'s emit-then-delete sequence check for already-registered listeners / use a persisted validation result keyed by unit that late listeners can query synchronously, avoiding reliance purely on one-shot event delivery timing.

### Proof of Concept
1. Peer submits a private payment chain to the wallet's hub/websocket handler (`wallet.js:955` `handlePrivatePaymentChains`) for unit `U`.
2. Because the chain requires an unfinished-past-unit fetch (light client) or is otherwise not immediately verifiable, `handleOnlinePrivatePayment` routes to `savePrivatePayment` and calls `ifQueued()` [4](#0-3) .
3. Concurrently (e.g., via `new_joint` handling or a background timer) `handleSavedPrivatePayments` is invoked, picks up the just-inserted `unhandled_private_payments` row for `U`, validates it, and emits `private_payment_validated-U-...` and deletes the row, all before the `wallet.js` `handlePrivatePaymentChains` call chain reaches the `eventBus.once(key, ...)` registration inside `ifQueued` [2](#0-1) .
4. The listener registered afterward in `wallet.js:1052-1060` never receives the already-fired event; `assocValidatedByKey[key]` stays `false` forever, `checkIfAllValidated` never completes, and the caller relying on `all_private_payments_handled`/`ifOk` for that chain hangs despite the private payment having been successfully validated and saved.

### Citations

**File:** network.js (L2390-2410)
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
	
	if (conf.bLight && arrPrivateElements.length > 1){
		savePrivatePayment(function(){
			updateLinkProofsOfPrivateChain(arrPrivateElements, unit, message_index, output_index);
			rerequestLostJointsOfPrivatePayments(); // will request the head element
		});
		return;
	}
```

**File:** network.js (L2478-2496)
```javascript
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
```

**File:** wallet.js (L1033-1062)
```javascript
			var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+output_index;
			assocValidatedByKey[key] = false;
			network.handleOnlinePrivatePayment(ws, arrPrivateElements, true, {
				ifError: function(error){
					console.log("handleOnlinePrivatePayment error: "+error);
					cb("an error"); // do not leak error message to the hub
				},
				ifValidationError: function(unit, error){
					console.log("handleOnlinePrivatePayment validation error: "+error);
					cb("an error"); // do not leak error message to the hub
				},
				ifAccepted: function(unit){
					console.log("handleOnlinePrivatePayment accepted");
					assocValidatedByKey[key] = true;
					cb(); // do not leak unit info to the hub
				},
				// this is the most likely outcome for light clients
				ifQueued: function(){
					console.log("handleOnlinePrivatePayment queued, will wait for "+key);
					eventBus.once(key, function(bValid){
						if (!bValid)
							return cancelAllKeys();
						assocValidatedByKey[key] = true;
						if (bParsingComplete)
							checkIfAllValidated();
						else
							console.log('parsing incomplete yet');
					});
					cb();
				}
```
