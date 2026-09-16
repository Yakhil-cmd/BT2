### Title
Unbounded processing of attacker-supplied private-payment chains causes memory exhaustion DoS - (File: wallet.js)

### Summary
`wallet.js`'s `handlePrivatePaymentChains()` accepts an arbitrarily large `chains` array from a paired device / private-payment counterparty and performs no bound on the number of chains, the length of each chain, or the size of the string fields inside each chain element (e.g. `blinding`, `output_hash`, `address`) before hashing, forwarding, and persisting the whole structure. This mirrors the Quill CVE pattern: attacker-controlled data is read/processed fully into memory with no size cap, enabling a memory-exhaustion DoS.

### Finding Description
`handlePrivatePaymentChains(ws, body, from_address, callbacks)` [1](#0-0)  validates only the *shape* of `body.chains` (non-empty array, objects have the right field names) — it never checks the number of chains, the length of any individual chain, or bounds the size of string fields such as `blinding` or `output_hash`. It then computes `objectHash.getBase64Hash(arrChains)` [2](#0-1)  and iterates every chain, calling `network.handleOnlinePrivatePayment` for each one [3](#0-2) .

Inside `handleOnlinePrivatePayment`, for light clients receiving a multi-element chain, the entire `arrPrivateElements` array is serialized with `JSON.stringify` and stored verbatim in the `unhandled_private_payments` table with no size limit check: [4](#0-3) .

This is unlike ordinary unit messages (`payment`, `data_feed`, `poll`, etc.), whose payload is always bounded because it is part of a unit and validated against `constants.MAX_UNIT_LENGTH` (5 MB) via `objectLength.getTotalPayloadSize` [5](#0-4) . Private-payment chains delivered as device/hub messages are never wrapped in a unit at the time they're first received and stored, so this 5 MB ceiling does not apply to them. The generic anti-DoS guard used elsewhere for hub messages, `isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000)` (used in `handleMessageFromHub`) [6](#0-5) , only counts array/object *nodes*, not the byte length of string leaf values — so a single giant string embedded in one of the chain elements' fields (e.g. `blinding`) would pass this check while still being arbitrarily large, exactly analogous to Quill reading an unbounded HTTP body into memory.

### Impact Explanation
A malicious paired device or private-payment counterparty can send a `private_payment_chains` message containing a very large `chains` array, or chain elements containing very large string fields, causing the recipient wallet/light client to allocate and hold this data fully in memory (during `objectHash.getBase64Hash`, `JSON.stringify`, and DB storage), and potentially do so repeatedly for multiple chains/messages, exhausting memory and crashing the wallet/node process — an availability impact matching CWE-770, consistent with the Medium severity of the referenced CVE.

### Likelihood Explanation
Any device paired with the victim wallet, or any peer legitimately participating in a private-payment/textcoin exchange, can send this message; no special privileges are required beyond being a paired correspondent or hub-relayed sender, matching the "private-payment counterparty" / "paired device" reachable actor allowed by scope.

### Recommendation
Add explicit bounds in `handlePrivatePaymentChains` (and `handleOnlinePrivatePayment`) on: the number of chains per message, the number of elements per chain, and the length of every string field in each private element (analogous to `MAX_DATA_FEED_VALUE_LENGTH`/`MAX_AUTHENTIFIER_LENGTH`-style constants), rejecting the message before any hashing/serialization/storage is performed.

### Proof of Concept
1. Pair a malicious device with a victim wallet (or become a private-payment counterparty).
2. Send a `private_payment_chains` message whose `body.chains` contains a very large array of chain arrays, or a single chain element with a multi-hundred-MB string in `output.blinding`/`output_hash`, while keeping node/array counts under 100000 to pass `isTooDeeplyNestedOrHasTooManyNodes`.
3. Observe `handlePrivatePaymentChains` → `objectHash.getBase64Hash(arrChains)` and `network.handleOnlinePrivatePayment` → `JSON.stringify(arrPrivateElements)` allocate memory proportional to the attacker-controlled payload size with no bound, leading to excessive memory consumption / crash on the victim's wallet process.

Note: I could not fully verify whether a lower-level WebSocket frame-size limit (`maxPayload` or similar, referenced in `network.js`) caps the overall message size before reaching this code; I found references to size-limit-related terms in `network.js` but ran out of tool calls to confirm their exact effect on this specific message path. This should be verified before treating the PoC as unconditionally exploitable at network layer, though it does not change the fact that no application-level bound exists in `handlePrivatePaymentChains`/`handleOnlinePrivatePayment` themselves.

### Citations

**File:** wallet.js (L64-66)
```javascript
function handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, callbacks){
	if (isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000))
		return callbacks.ifError("message from hub is too deeply nested or has too many nodes");
```

**File:** wallet.js (L955-972)
```javascript
function handlePrivatePaymentChains(ws, body, from_address, callbacks){
	var arrChains = body.chains;
	if (!ValidationUtils.isNonemptyArray(arrChains))
		return callbacks.ifError("no chains found");
	if (!arrChains.every(c =>
		isNonemptyArray(c) &&
		c.every(e =>
			isNonemptyObject(e) &&
			isNonemptyString(e.unit) &&
			isNonemptyObject(e.payload) &&
			isNonemptyString(e.payload.asset) &&
			isNonemptyArray(e.payload.inputs) &&
			isNonemptyArray(e.payload.outputs) &&
			e.payload.inputs.every(isNonemptyObject) &&
			e.payload.outputs.every(isNonemptyObject)
		)
	))
		return callbacks.ifError("malformed private chain");
```

**File:** wallet.js (L973-978)
```javascript
	try {
		var cache_key = objectHash.getBase64Hash(arrChains);
	}
	catch (e) {
		return callbacks.ifError("chains hash failed: " + e.toString());		
	}
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

**File:** validation.js (L257-268)
```javascript
		if (objectLength.getHeadersSize(objUnit) !== objUnit.headers_commission)
			return callbacks.ifJointError("wrong headers commission, expected "+objectLength.getHeadersSize(objUnit));
		try {
			const payloadSize = objectLength.getTotalPayloadSize(objUnit);
			if (payloadSize !== objUnit.payload_commission)
				return callbacks.ifJointError("wrong payload commission, unit " + objUnit.unit + ", expected " + payloadSize);
		}
		catch (e) {
			return callbacks.ifJointError("failed to calculate payload commission: " + e);
		}
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis && !bAA)
			return callbacks.ifUnitError("unit too large");
```
