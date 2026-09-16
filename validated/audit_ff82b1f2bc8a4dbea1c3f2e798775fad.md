### Title
Orphaned private-payment validation promise causes permanent hang and listener/memory accumulation on the counterparty's node - ([File: network.js])

### Summary
`network.js`'s `handleSavedPrivatePayments()` has a code path where, after a private-payment payload fails to hash, the function deletes the queued row but **falls through without returning**, corrupting the event key used to notify whoever is awaiting validation of that private-payment chain. This mirrors the undici bug class: a response/result object is silently abandoned while a reader elsewhere keeps waiting on it forever, accumulating orphaned promises/listeners with no timeout tied to the actual resource.

### Finding Description
Private payments (used for asset-private payments/textcoins between wallets, reachable by any private-payment counterparty) are queued into `unhandled_private_payments` and later processed by `handleSavedPrivatePayments()`: [1](#0-0) 

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

There is no `return` inside the `catch` block. On a hashing failure:
1. `deleteHandledPrivateChain(...)` removes the row from `unhandled_private_payments` and asynchronously calls `cb()` for the outer `async.each`.
2. Execution nonetheless continues synchronously past the `catch`, builds a *corrupted* key (`json_payload_hash` is `undefined`, so the key literally contains the string `"undefined"`), and re-invokes `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, …)` on the same, already-deleted chain a second time.
3. Any legitimate waiter that queued the same chain earlier and is listening for the *correct* key will never see a matching `eventBus.emit(key, …)`.

Two independent callers create such long-lived waiters keyed off `objectHash.getBase64Hash(payload, true)` of the very same private-payment head element:

- `wallet.js`'s `handlePrivatePaymentChains()` `ifQueued` branch, used whenever a paired device or hub relays a private chain that cannot be validated synchronously (the documented "most likely outcome for light clients"): [2](#0-1) 

- `wallet.js`'s `handlePrivatePaymentFile()` (textcoin claiming), which waits on `'all_private_payments_handled-'+first_chain_unit` — itself only emitted from `checkIfAllValidated()` once every per-chain key has resolved: [3](#0-2) [4](#0-3) 

Because `deleteHandledPrivateChain`/`validateAndSavePrivatePaymentChain` in `network.js` never fires the key that the waiter is actually registered on, `eventBus.once(key, …)` never triggers. This is exactly the same bug class as CVE-2026-18149: the "handler" (here, the private-payment processing loop) discards/replaces the state backing a promise a caller is holding, without ever settling it, and the code has no independent timeout tied to that specific promise (unlike a network request, there is no `RESPONSE_TIMEOUT`/mutex-timeout analog protecting this in-process event-based rendezvous).

### Impact Explanation
Each private-payment chain sent by a counterparty (direct peer, or relayed via hub/paired device) that triggers this code path leaves behind a permanently pending `eventBus.once` listener and a permanently unresolved completion path:
- `handlePrivatePaymentChains`'s `checkIfAllValidated()` will never see all keys validated, so `all_private_payments_handled`/`all_private_payments_handled-<unit>` is never emitted for that batch, silently breaking forwarding of the private chain to other members of shared addresses (`forwardPrivateChainsToOtherMembersOfSharedAddresses`).
- `handlePrivatePaymentFile()`'s `cb(null, data)` callback for textcoin redemption never fires, hanging the redemption flow indefinitely for the user.
- Repeated attempts accumulate orphaned `eventBus` listeners and closures (each retaining `arrChains`, `assocValidatedByKey`, etc.), growing unbounded memory/listener usage on the victim's node — the same "requests pile up and exhaust concurrency or memory" outcome described in the CVE, driven by an unprivileged private-payment counterparty rather than a malicious HTTP server.

### Likelihood Explanation
Triggering requires making `objectHash.getBase64Hash()` throw on a payload that otherwise passes the loose, non-cryptographic shape checks performed before it is queued (`isNonemptyObject`/`isNonemptyString`/`isNonemptyArray` checks in `wallet.js:959-972` and the minimal validation in `handleOnlinePrivatePayment`, `network.js:2376-2441`), since private payments are only fully cryptographically validated later, inside `validateAndSavePrivatePaymentChain`. Because the full space of payload shapes that reach the hashing call has not been exhaustively audited here, I could not conclusively confirm a concrete payload that makes `getBase64Hash` throw without deeper testing of `object_hash.js`'s canonicalization rules; this is the main open uncertainty. However, the missing `return` after the `catch` is an unambiguous, provable control-flow bug independent of the exact trigger, and it is reachable by an unprivileged private-payment counterparty who controls the payload content end-to-end.

### Recommendation
- Add a `return` immediately after `deleteHandledPrivateChain(...)` inside the `catch` block in `handleSavedPrivatePayments()` (`network.js`), and additionally emit the (best-effort) validation key with `false`/error before returning, so that any caller waiting via `eventBus.once(key, …)` is released rather than orphaned.
- Consider adding a bounded timeout for the `eventBus.once(key, …)` waits in `wallet.js` (`handlePrivatePaymentChains`'s `ifQueued` handler and `handlePrivatePaymentFile`), so that even if a corresponding emit is missed for other/future reasons, the waiter is not blocked forever.
- Audit `objectHash.getBase64Hash` for the specific payload shapes that can throw, and ensure `handleOnlinePrivatePayment`/`savePrivatePayment` reject such malformed private-payment payloads before they are queued, rather than deferring the failure to the asynchronous `handleSavedPrivatePayments` pass.

### Proof of Concept
1. As a private-payment counterparty (or a device relaying on behalf of one), send a `private_payment`/`private_payment_chains` message whose head element's `payload` passes the shallow `isNonemptyObject`/`isNonemptyArray` checks in `handleOnlinePrivatePayment` (`network.js:2376-2441`) and `handlePrivatePaymentChains` (`wallet.js:955-983`), but is crafted so that `objectHash.getBase64Hash(payload, true)` throws when later invoked on the JSON-round-tripped copy read back from `unhandled_private_payments` (exact payload shape not confirmed in this review; would need to be found via targeted testing of `object_hash.js`).
2. The receiving wallet queues the chain and registers `eventBus.once('private_payment_validated-<unit>-<hash>-<output_index>', …)` in `handlePrivatePaymentChains`'s `ifQueued` path.
3. On the next `handleSavedPrivatePayments()` tick, `getBase64Hash` throws for the head element; the code deletes the row and falls through, emitting (if anything) a key containing `undefined` instead of `<hash>`.
4. The listener registered in step 2 never fires; `checkIfAllValidated()` never completes for this chain, and any process (e.g., `handlePrivatePaymentFile`) awaiting `all_private_payments_handled-<unit>` hangs indefinitely. Repeating the attack accumulates additional permanently-pending `eventBus` listeners on the victim's node.

### Citations

**File:** network.js (L2467-2504)
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
```

**File:** wallet.js (L998-1018)
```javascript
	var checkIfAllValidated = function(){
		if (!assocValidatedByKey) // duplicate call - ignore
			return console.log('duplicate call of checkIfAllValidated');
		for (var key in assocValidatedByKey)
			if (!assocValidatedByKey[key])
				return console.log('not all private payments validated yet');
		eventBus.emit('all_private_payments_handled', from_address);
		eventBus.emit('all_private_payments_handled-' + arrChains[0][0].unit);
		assocValidatedByKey = null; // to avoid duplicate calls
		if (!body.forwarded){
			if (from_address) emitNewPrivatePaymentReceived(from_address, arrChains, current_message_counter);
			// note, this forwarding won't work if the user closes the wallet before validation of the private chains
			var arrUnits = arrChains.map(function(arrPrivateElements){ return arrPrivateElements[0].unit; });
			db.query("SELECT address FROM unit_authors WHERE unit IN(?)", [arrUnits], function(rows){
				var arrAuthorAddresses = rows.map(function(row){ return row.address; });
				// if the addresses are not shared, it doesn't forward anything
				forwardPrivateChainsToOtherMembersOfSharedAddresses(arrChains, arrAuthorAddresses, from_address, true);
			});
		}
		profiler.print();
	};
```

**File:** wallet.js (L1049-1062)
```javascript
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

**File:** wallet.js (L2905-2914)
```javascript
					eventBus.once('all_private_payments_handled-' + first_chain_unit, function(){
						cb(null, data);
					});
					var onDone = function() {
						handlePrivatePaymentChains(ws, data, null, {
							ifError: function(err){
								cb(err);
							},
							ifOk: function(){} // we subscribe to event, not waiting for callback
						});
```
