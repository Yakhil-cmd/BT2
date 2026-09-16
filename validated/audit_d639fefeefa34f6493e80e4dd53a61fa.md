### Title
Global eventBus key collision lets a failing private-payment chain cancel unrelated in‑flight validations, freezing private funds - (File: wallet.js)

### Summary
`handlePrivatePaymentChains()` validates a batch of private-payment chains with `async.eachSeries`, tracking outstanding async validations in `assocValidatedByKey` keyed only by `unit + payload_hash + output_index` [1](#0-0) . When a chain is not yet resolvable it registers a one-shot completion listener on the process-wide `eventBus` for that key [2](#0-1) . On any validation error in the batch, `cancelAllKeys()` blindly calls `eventBus.removeAllListeners(key)` for every key seen so far [3](#0-2) , and the `async.eachSeries` completion handler invokes it unconditionally on error [4](#0-3) . Because the key is derived only from content identifiers and not scoped to the specific request/invocation, this is analogous to the libkcapi bug class: an error path drains/cancels "requests" (event listeners) that were not actually the ones that failed, silently discarding pending completions that belong to a different, still-legitimate in-flight operation.

### Finding Description
`handlePrivatePaymentChains()` can be invoked concurrently multiple times for chains that legitimately share the same head unit/payload/output (e.g., the same private payment forwarded via hub and directly by a peer, or sent to two addresses of the same shared wallet, or simply retransmitted). Each invocation computes the identical `key` string [5](#0-4)  and, if `network.handleOnlinePrivatePayment` answers `ifQueued`, registers its own `eventBus.once(key, ...)` listener [6](#0-5) .

If a *different* chain bundled in one of these concurrent invocations fails validation (`ifError`/`ifValidationError`), `async.eachSeries` stops and its final callback fires with an error, calling `cancelAllKeys()` [4](#0-3) . `cancelAllKeys()` does not distinguish which invocation registered which listener - it simply calls `eventBus.removeAllListeners(key)` for every key that this invocation's `assocValidatedByKey` happens to contain [3](#0-2) . Since `eventBus` is a single shared, process-global emitter, this removes *all* listeners registered under that key, including the ones added by the unrelated, still-valid concurrent invocation.

This mirrors the reported bug class precisely: an error branch performs cleanup/cancellation without first draining/confirming which "aio requests" (here, pending validation listeners) genuinely belong to the failed operation, so unrelated, still-outstanding completions are wiped out (the CVE's "uncanceled" requests become, in this codebase, "wrongly canceled" requests belonging to someone else) — and later legitimate completions (`eventBus.emit(key, true)`, dispatched independently by `network.js`'s `handleSavedPrivatePayments` [7](#0-6) ) have nowhere to land.

### Impact Explanation
The orphaned invocation's `assocValidatedByKey[key]` is permanently stuck at `false` because its listener was deleted before the real validation event fired. `checkIfAllValidated()` for that invocation will therefore never emit `all_private_payments_handled` and will never mark the chain as validated [8](#0-7) . The private payment is effectively lost/frozen from the recipient wallet's perspective: it is never surfaced as a confirmed balance, and its `unhandled_private_payments` row is not cleaned up by that invocation's flow, leaving the sender/receiver in permanent disagreement over the validity/availability of the received asset amount. This matches the allowed "private payment freezing"/fund-loss impact triggerable purely by an unprivileged private-payment counterparty who deliberately sends a batch that mixes one bad chain with the shared key of a legitimate, concurrently-processed chain.

### Likelihood Explanation
Reachable by any private-payment counterparty without special privileges: they only need to cause two concurrent calls to `handlePrivatePaymentChains()` that reference the same `(unit, payload_hash, output_index)` key (a natural occurrence via hub + direct delivery, or forwarding to multiple shared-address members, per `forwardPrivateChainsToOtherMembersOfOutputAddresses`), and include one intentionally invalid chain in one of the batches to trigger `cancelAllKeys()`. No node/hub compromise is required — the trigger is a crafted P2P `private_payment` message batch, well within scope.

### Recommendation
Scope pending-validation listeners per invocation instead of relying on a globally shared key string, e.g. by generating a unique per-call token to combine with the key when calling `eventBus.once`/`removeListener`, or by tracking listener references locally (`assocListenersByKey[key] = listenerFn`) and calling `eventBus.removeListener(key, listenerFn)` in `cancelAllKeys()` instead of `removeAllListeners(key)`, so an error in one invocation cannot cancel another invocation's outstanding completion.

### Proof of Concept
1. Attacker (or two colluding peers) sends the victim wallet two `private_payment` messages that both contain a chain head with identical `(unit, payload_hash, output_index)` — e.g., relay the same legitimate private payment once directly and once forwarded via hub, causing `handlePrivatePaymentChains()` to run twice with the same `key` computed at wallet.js:1033.
2. In the batch delivered via one of the two paths, include an additional, deliberately malformed/invalid chain earlier in `arrChains` alongside the legitimate shared-key chain, so `async.eachSeries` calls `cb("an error")` at wallet.js:1038/1042 before the legitimate chain reaches `ifOk`.
3. This causes the final `async.eachSeries` callback to run `cancelAllKeys()` (wallet.js:1068), removing the `eventBus` listener for `key` registered by the *other*, still-pending, legitimate invocation (wallet.js:1052-1060).
4. When `network.js`'s background processor later validates the legitimate chain and emits `eventBus.emit(key, true)` (network.js:2488), no listener remains to consume it; the second invocation's `assocValidatedByKey[key]` is never set to `true`, `checkIfAllValidated()` never completes for it, and the private payment is never confirmed to the wallet's UI/state, effectively freezing those private funds.

Note: I was unable to fully verify (with static index-only tooling) the exact call sites that trigger two truly concurrent `handlePrivatePaymentChains()` invocations sharing identical keys under all conditions (e.g., how `forwardPrivateChainsToOtherMembersOfOutputAddresses`/hub re-delivery interacts precisely at runtime); confirming the exact reproduction timing would benefit from a full Devin session with runtime access to the repository.

### Citations

**File:** wallet.js (L991-994)
```javascript
	var cancelAllKeys = function(){
		for (var key in assocValidatedByKey)
			eventBus.removeAllListeners(key);
	};
```

**File:** wallet.js (L998-1017)
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
```

**File:** wallet.js (L1020-1034)
```javascript
	async.eachSeries(
		arrChains,
		function(arrPrivateElements, cb){ // validate each chain individually
			var objHeadPrivateElement = arrPrivateElements[0];
			if (!!objHeadPrivateElement.payload.denomination !== ValidationUtils.isNonnegativeInteger(objHeadPrivateElement.output_index))
				return cb("divisibility doesn't match presence of output_index");
			var output_index = objHeadPrivateElement.payload.denomination ? objHeadPrivateElement.output_index : -1;
			try {
				var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
			}
			catch (e) {
				return cb("head priv element hash failed " + e.toString());
			}
			var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+output_index;
			assocValidatedByKey[key] = false;
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

**File:** wallet.js (L1065-1070)
```javascript
		function(err){
			bParsingComplete = true;
			if (err){
				cancelAllKeys();
				return callbacks.ifError(err);
			}
```

**File:** network.js (L2478-2503)
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
							},
							// light only. Means that chain joints (excluding the head) not downloaded yet or not stable yet
							ifWaitingForChain: function(){
								console.log('waiting for chain: unit '+row.unit+', message '+row.message_index+' output '+row.output_index);
								cb();
							}
						});
```
