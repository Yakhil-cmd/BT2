## Finding

### Title
Private payment chains are marked "handled" in `handledChainsCache` before asynchronous validation actually completes, letting a resend of the same chains bypass validation entirely - ([File: wallet.js])

### Summary
`handlePrivatePaymentChains()` in `wallet.js` caches a "this exact set of private-payment chains was handled" flag (`handledChainsCache[cache_key]`) immediately after the `async.eachSeries` loop over the chains finishes its synchronous pass - not after the actual (often asynchronous) cryptographic/ledger validation of each chain element has confirmed success. On a resend of the identical chains, the cache short-circuits all validation and immediately reports success, exactly analogous to the curl bug where a cached SSL session ID let a later transfer skip the OCSP/verify-status check that had failed.

### Finding Description
In `handlePrivatePaymentChains()`: [1](#0-0) 
the function computes `cache_key = objectHash.getBase64Hash(arrChains)` from the attacker/peer-controlled request body, and if that key is already present in `handledChainsCache`, it unconditionally emits the "handled" events and calls `callbacks.ifOk()` without doing any validation: [2](#0-1) 

The cache entry itself is populated here: [3](#0-2) 

The critical defect is in the `ifQueued` branch of the per-chain validation callback passed to `network.handleOnlinePrivatePayment`: [4](#0-3) 
When a chain element cannot be validated synchronously (the "most likely outcome for light clients"), `cb()` for `async.eachSeries` is invoked immediately, *before* the real result is known; the real result only arrives later via `eventBus.once(key, ...)`. Because `async.eachSeries`'s final callback fires as soon as all `cb()` calls have been invoked (regardless of whether they represent real success), the completion handler: [5](#0-4) 
sets `handledChainsCache[cache_key] = Date.now();` and calls `callbacks.ifOk()` unconditionally, even though the true verification outcome for the queued element(s) is still pending.

If that pending verification later fails, the `eventBus.once(key, ...)` handler calls `cancelAllKeys()`: [6](#0-5) 
but `cancelAllKeys()` only removes event listeners — it never deletes the already-set `handledChainsCache[cache_key]` entry: [7](#0-6) 

The cache is only pruned by age (1 hour) via a periodic interval, not by validation outcome: [8](#0-7) 

Consequently, once a peer/paired device causes a particular `arrChains` payload to be queued and the loop to complete once, that exact payload is permanently (for up to 1 hour) marked as "handled" in the cache — independent of whether the underlying private-payment validation (signatures, amounts, spend-proofs) ultimately succeeded or failed.

### Impact Explanation
`handlePrivatePaymentChains` is invoked from device-message handling for private payments sent by a paired correspondent/private-payment counterparty (a reachable, unprivileged actor per the wiki's private-payment chain surface). By crafting a set of private payment chains that get queued (the documented common case for light clients) and whose real validation subsequently fails (e.g. because it's an invalid/double-spent/forged private payment), an attacker can:
1. Cause `handledChainsCache[cache_key]` to be set to a "success" timestamp despite validation failing.
2. Resend the identical `arrChains` body (a device message the attacker fully controls and can replay) any number of times within the cache TTL.
3. Each resend takes the `handledChainsCache[cache_key]` branch, which emits `all_private_payments_handled` and calls `callbacks.ifOk()` — the same code path used to signal a genuinely accepted private payment — without ever revalidating the payment.

Because `all_private_payments_handled`/`ifOk()` drives downstream wallet logic (marking the private payment as received/accepted, notifying UI, potentially triggering forwarding to other cosigners of shared addresses), this allows an invalid or double-spent private payment to be treated by the receiving wallet as accepted, i.e., acceptance/spending logic proceeds on a payment that never actually passed validation. This is a concrete instance of a node disagreeing on validity of a private-payment output, with a path to loss/incorrect crediting of private-asset funds.

### Likelihood Explanation
The trigger is entirely under the control of a private-payment counterparty / paired device sending a `private_payment_chains` message — no privileged access, no network-level attack, and no race condition beyond resending an identical message the sender already possesses (since they constructed the original chains). The `ifQueued` path is explicitly noted in the code comment as "the most likely outcome for light clients," making the caching-before-validation window a common occurrence rather than an edge case.

### Recommendation
- Do not populate `handledChainsCache[cache_key]` until `checkIfAllValidated()`'s success path has actually run (i.e., all `assocValidatedByKey` entries are true), not merely after `async.eachSeries` has iterated once.
- On validation failure signaled via `eventBus.once(key, ...)` with `bValid === false`, explicitly delete `handledChainsCache[cache_key]` (in addition to `cancelAllKeys()`), so a failed validation cannot be "remembered" as success.
- Consider gating the whole short-circuit block at the top of `handlePrivatePaymentChains` on a per-key "validated" flag rather than a bare presence check, so a still-pending or failed validation can never be conflated with a confirmed one.

### Proof of Concept
1. A paired device sends `handlePrivatePaymentChains` a message whose private payment chain(s) cannot be validated synchronously (light-client `ifQueued` path is taken for at least one chain element).
2. `async.eachSeries` completes its single pass (all `cb()` calls fired from `ifQueued`), so the final callback runs, calling `checkIfAllValidated()` (a no-op here since `assocValidatedByKey` is still false) and then unconditionally `handledChainsCache[cache_key] = Date.now();` and `callbacks.ifOk();`.
3. Shortly after, the real validation (asynchronously delivered via `eventBus.once(key, ...)`) determines the payment is invalid, calling `cancelAllKeys()` — but `handledChainsCache[cache_key]` is left untouched.
4. The attacker resends the exact same `arrChains` body. `handledChainsCache[cache_key]` is still set, so `handlePrivatePaymentChains` immediately hits the branch at lines 979-983, emits `all_private_payments_handled`, and calls `callbacks.ifOk()` — reporting the invalid private payment as accepted, without any revalidation.

### Citations

**File:** wallet.js (L948-953)
```javascript
var handledChainsCache = {};
setInterval(() => {
	for (let cache_key in handledChainsCache)
		if (handledChainsCache[cache_key] < Date.now() - 3600 * 1000)
			delete handledChainsCache[cache_key];
}, 3600 * 1000); // clear cache every hour
```

**File:** wallet.js (L973-983)
```javascript
	try {
		var cache_key = objectHash.getBase64Hash(arrChains);
	}
	catch (e) {
		return callbacks.ifError("chains hash failed: " + e.toString());		
	}
	if (handledChainsCache[cache_key]) {
		eventBus.emit('all_private_payments_handled', from_address);
		eventBus.emit('all_private_payments_handled-' + arrChains[0][0].unit);
		return callbacks.ifOk();
	}
```

**File:** wallet.js (L991-994)
```javascript
	var cancelAllKeys = function(){
		for (var key in assocValidatedByKey)
			eventBus.removeAllListeners(key);
	};
```

**File:** wallet.js (L1020-1078)
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
			});
		},
		function(err){
			bParsingComplete = true;
			if (err){
				cancelAllKeys();
				return callbacks.ifError(err);
			}
			checkIfAllValidated();
			handledChainsCache[cache_key] = Date.now();
			callbacks.ifOk();
			// forward the chains to other members of output addresses
			if (!body.forwarded)
				forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, true);
		}
	);
```
