### Title
Global private-payment dedup cache shared across all counterparties bypasses per-sender validation - (File: wallet.js)

### Summary
`handlePrivatePaymentChains` in `wallet.js` uses a single, global, content-keyed cache (`handledChainsCache`) to short-circuit validation of incoming private payment chains. The cache key is derived only from the hash of the chain content (`objectHash.getBase64Hash(arrChains)`), with no binding to the sender (`from_address`), the connection (`ws`), or the recipient wallet. This mirrors the Hawtio flaw where a single shared HTTP client/cookie store caused state meant to be scoped to one client to leak across all clients using the proxy — here, a validation-result cache meant to reflect "this exact chain content was already verified" is treated as universally trusted regardless of who is now presenting it or to whom.

### Finding Description
`handlePrivatePaymentChains` computes `cache_key = objectHash.getBase64Hash(arrChains)` from the chain payloads only [1](#0-0) , and if that key exists in `handledChainsCache`, it immediately emits `'all_private_payments_handled'` for the *current* `from_address` and calls `callbacks.ifOk()` without re-running `network.handleOnlinePrivatePayment` validation, without re-checking `requestUnfinishedPastUnitsOfPrivateChains`, and without re-deriving `assocValidatedByKey`/`checkIfAllValidated` state for this specific caller [2](#0-1) .

The cache is populated only after the full validation path succeeds for the *original* sender via `async.eachSeries` over `arrChains` calling `network.handleOnlinePrivatePayment` [3](#0-2) , and is written unconditionally with `handledChainsCache[cache_key] = Date.now();` on success [4](#0-3) .

Because the cache entry is keyed purely by chain-content hash and is process-wide (shared by every device/peer connection handled by this wallet instance), any subsequent submitter — including one presenting the identical private-chain JSON via a different `ws`/`from_address` — is granted the "already validated" fast path. This is architecturally identical to Hawtio's bug class: a single shared piece of validated/session state (there: cookies in a shared `HttpClient`; here: a validation verdict in a shared cache) that should be scoped per request/party is instead treated as globally applicable, letting one party's session state affect another party's outcome.

### Impact Explanation
On the "already handled" path, the code skips `emitNewPrivatePaymentReceived`, `forwardPrivateChainsToOtherMembersOfSharedAddresses`, and `forwardPrivateChainsToOtherMembersOfOutputAddresses` for the new caller's context because those only run inside `checkIfAllValidated`'s "not body.forwarded" branch which is bypassed entirely [5](#0-4) . This means a second device/peer can replay a previously-seen private chain payload and have the wallet unconditionally believe (and signal to its UI/event bus via `all_private_payments_handled`) that the payment was received/validated for them, without the underlying `network.handleOnlinePrivatePayment` double-spend/output-ownership checks being re-executed for that specific caller/context. In a private-payment (asset transfer) system, this creates a path where validation state legitimately established for one counterparty is silently reused to short-circuit due diligence for a different counterparty presenting the same bytes — undermining per-counterparty double-spend and authenticity guarantees that `handleOnlinePrivatePayment` is meant to enforce for each caller.

### Likelihood Explanation
Any peer or device that can reach `handlePrivatePaymentChains` (this is the private-payment message handler invoked from a hub/device connection, reachable by any paired device or private-payment counterparty) can trigger this by simply resending a chain payload previously validated for someone else — no privileged access is required, and the trigger condition (matching content hash) is deterministic and attacker-controllable since the attacker can craft/replay exact `arrChains` content.

### Recommendation
Bind `handledChainsCache` entries to the requesting context, not just chain content — e.g., include `from_address` (and/or `ws`/connection identity) in the cache key, or scope the cache per-recipient wallet/address, so a validation result established for one sender cannot be replayed to short-circuit validation for another sender or connection. Alternatively, remove the shortcut entirely and always re-run `network.handleOnlinePrivatePayment` per caller, using the cache only to avoid redundant expensive re-validation for the *same* sender/connection pair.

### Proof of Concept
1. Device A sends a valid `private_payment_chain` message with chain content `C` to the wallet; `handlePrivatePaymentChains` validates it via `network.handleOnlinePrivatePayment`, succeeds, and stores `handledChainsCache[hash(C)] = now` [6](#0-5) .
2. Device B (a different device/peer, different `from_address`) subsequently sends the exact same chain content `C` (replaying the observed message, e.g. from having witnessed it in transit or from a stale/forwarded copy).
3. `handlePrivatePaymentChains` computes the same `cache_key` and, finding it in `handledChainsCache`, immediately emits `'all_private_payments_handled'` for Device B's `from_address` and calls `callbacks.ifOk()` — without re-validating ownership/spend status for Device B's context [7](#0-6) .
4. The wallet UI/event consumers for Device B's session treat the payment as fully validated/received, even though no per-connection validation occurred for that specific request.

### Citations

**File:** wallet.js (L973-978)
```javascript
	try {
		var cache_key = objectHash.getBase64Hash(arrChains);
	}
	catch (e) {
		return callbacks.ifError("chains hash failed: " + e.toString());		
	}
```

**File:** wallet.js (L979-988)
```javascript
	if (handledChainsCache[cache_key]) {
		eventBus.emit('all_private_payments_handled', from_address);
		eventBus.emit('all_private_payments_handled-' + arrChains[0][0].unit);
		return callbacks.ifOk();
	}
	profiler.increment();
	
	if (conf.bLight)
		network.requestUnfinishedPastUnitsOfPrivateChains(arrChains); // it'll work in the background
	
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

**File:** wallet.js (L1020-1063)
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
```

**File:** wallet.js (L1065-1077)
```javascript
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
```
