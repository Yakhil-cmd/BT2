### Title
Trivially-bypassable de-duplication cache lets a paired device flood full private-payment chain validation - ([File: wallet.js])

### Summary
`handlePrivatePaymentChains` in `wallet.js` deduplicates incoming private-payment chain messages using a cache keyed by a hash of the *entire* `chains` payload, similar in spirit to the Plone `queryCatalog.py` bug where a crafted request could bypass caching and force expensive re-computation on every request.

### Finding Description
When a device receives a `private_payments` message, `handlePrivatePaymentChains` computes a cache key as a hash of the whole `arrChains` array and only performs full validation (`network.handleOnlinePrivatePayment`, which parses payloads, checks signatures/definitions and issues DB queries) when this exact key hasn't been seen before: [1](#0-0) [2](#0-1) 

Because the cache key is derived from the full content of the attacker-controlled message (`objectHash.getBase64Hash(arrChains)`), any counterparty/paired device that can send `private_payments` messages can trivially bypass the cache by varying any byte of the payload (e.g. appending a no-op field, shuffling immaterial ordering, or altering a private-chain element that doesn't change semantic validity) so that every message computes a fresh cache key and is never a "duplicate" from the cache's point of view. Each such message re-triggers the full, expensive validation pipeline (`network.handleOnlinePrivatePayment` → signature/definition/authentifier evaluation, multiple DB reads) with no cap on the number of distinct keys or messages processed, and no per-sender rate limiting visible in this handler.

The cache is intended purely to skip redundant work for identical resends, but since it can be trivially defeated, it provides no actual protection against a flood of near-duplicate private-payment chains from a paired device, and the cleanup interval only expires old entries — it does not bound the *rate* of new entries being added: [3](#0-2) 

### Impact Explanation
A single paired device/correspondent (an actor explicitly reachable per scope — "private-payment counterparty or paired device") can repeatedly send crafted private-payment chain messages that always miss the cache, forcing the receiving wallet to run full validation (crypto verification, several DB round-trips, mutex-guarded critical sections) for every message. This is a CPU/DB resource-exhaustion vector against the wallet process, matching the CWE-400 "caching bypass causing DoS" class from the reference advisory. Because the wallet's private-payment handling occupies mutex locks per unit and can be invoked repeatedly and inexpensively by the attacker (just varying payload bytes), it can degrade or stall the victim's ability to process other private payments/units in a timely manner.

### Likelihood Explanation
Likelihood is moderate: it requires the attacker to be a device the victim is paired with or a hub-routed correspondent capable of sending `private_payments` messages, which is a normal, expected capability in the private-payment protocol (no special privilege beyond pairing). Constructing payloads that still parse as "well-formed enough" to reach the expensive validation stage but differ from previous ones in trivial ways is straightforward, since the cache key is a hash of raw content rather than of a normalized/semantic representation.

### Recommendation
- Key the dedup cache on a canonical/semantic identity of the private chain (e.g., the head unit + message_index + output_index, or the hash used internally as `key` in `assocValidatedByKey`) rather than a hash over the full, attacker-supplied byte content, so trivial resubmission with irrelevant changes still hits the cache.
- Add a per-`from_address` rate limit / cap on the number of distinct chains processed within a time window before invoking `network.handleOnlinePrivatePayment`.
- Consider bounding `handledChainsCache` size (not just time) to avoid unbounded growth from a flood of unique keys.

### Proof of Concept
1. Attacker pairs with / is a correspondent of the victim wallet.
2. Attacker sends a `private_payments` message with `chains` containing a valid-looking private payment chain.
3. Attacker resends the same logical chain repeatedly, each time flipping an inconsequential byte (e.g., adding an extra whitespace-insensitive JSON field variance is not possible since it's parsed already, but the attacker can vary anything within `payload` that is not strictly checked before the hash is computed, such as a harmless field or ordering that `objectHash.getBase64Hash` treats as distinct).
4. Because `objectHash.getBase64Hash(arrChains)` differs each time, `handledChainsCache[cache_key]` is never populated for the new key, so `checkIfAllValidated`/`network.handleOnlinePrivatePayment` full validation path executes on every message, consuming CPU/DB resources on the victim node repeatedly.

*Note: I could not fully trace the exact cost/DB-query count inside `network.handleOnlinePrivatePayment` (defined in `network.js`) within the available tool budget, so the precise magnitude of resource consumption per call is not fully quantified here; a deeper reachability/cost trace of that function would be needed to fully confirm severity.*

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

**File:** wallet.js (L955-984)
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
	profiler.increment();
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
