### Title
Unbounded growth of queued private-payment validation listeners and `handledChainsCache` entries - ([File: wallet.js])

### Summary
`handlePrivatePaymentChains()` in `wallet.js` mirrors the BIND async-cleanup pattern from CVE-2023-6516: each incoming request allocates a small pending-cleanup-style record (an `eventBus.once` listener plus an `assocValidatedByKey` flag) that is only reclaimed when a *later, asynchronous* event fires. A paired device (an "unprivileged... private-payment counterparty" per the allowed actor list) can keep sending distinct `private_payments` messages fast enough that these pending records accumulate without any hard cap, exactly like BIND's queued cache-cleanup events outpacing their processing.

### Finding Description
`handlePrivatePaymentChains(ws, body, from_address, callbacks)` [1](#0-0)  is reachable from any correspondent/paired device sending a `private_payments` device message and only requires the payload to satisfy shallow structural checks (`isNonemptyObject`/`isNonemptyString`/`isNonemptyArray`) before being processed [2](#0-1) .

For each element of each chain, the code registers a key in `assocValidatedByKey` and calls `network.handleOnlinePrivatePayment`. For light clients — the documented "most likely outcome" — the callback path is `ifQueued`, which immediately registers a one-time listener on the global `eventBus` for a key derived from the unit/hash/output_index and calls `cb()` right away, without waiting for the referenced unit to ever arrive: [3](#0-2) .

That listener is only removed in two cases: (1) the awaited event actually fires (which requires the corresponding unit to eventually be delivered and validated), or (2) `cancelAllKeys()` is invoked when a *later* chain element in the same call fails synchronously [4](#0-3) , [5](#0-4) . If the sender simply never follows up with the referenced units (or references unit IDs that will never validate/arrive), the `eventBus.once(key, ...)` listener — and the closures it captures (`arrChains`, `ws`, `assocValidatedByKey`, etc.) — remain resident in memory indefinitely. There is no timeout, TTL, or maximum count enforced on these pending listeners, unlike the periodic, bounded caches elsewhere in the codebase (e.g. `archiving.js`'s `assocCachedPrunedJoints`, purged every hour by TTL, or `storage.js`'s `shrinkCache()` which caps unit-related caches at `MAX_ITEMS_IN_CACHE`) [6](#0-5) .

In addition, on successful completion of a batch, `handledChainsCache[cache_key] = Date.now()` is recorded, keyed by a hash of the entire request body, and is only pruned once per hour by matching `Date.now()` against a 1-hour-old timestamp — with no cap on the total number of distinct keys that can accumulate within that hour [7](#0-6) , [8](#0-7) . This is structurally identical to BIND's cache-cleanup queue: small allocations are queued for later asynchronous reclamation, and if the rate of triggering requests exceeds the rate of reclamation (here, gated by a 1-hour interval or by units that may never arrive), the queue/cache grows without the intended bound.

### Impact Explanation
An attacker controlling a paired device/correspondent can repeatedly send `private_payments` messages referencing distinct, never-to-be-delivered units (or simply large volumes of unique chains), causing the victim wallet/light-client process to accumulate an unbounded number of `eventBus` listeners and `handledChainsCache` entries in memory. Sustained abuse leads to memory exhaustion of the node process, denial of service for the local wallet, and in Node.js can also raise `MaxListenersExceededWarning`/degrade `eventBus` performance for all other consumers of the same global event bus (which is used throughout the codebase, including consensus-relevant flows like AA responses and unit propagation), effectively causing the node to become unresponsive to legitimate traffic.

### Likelihood Explanation
Reachability is straightforward: this code path is entered by any correspondent that a wallet already communicates with over the paired-device channel, with only shallow structural validation gating entry (`isNonemptyObject`/`isNonemptyArray`/`isNonemptyString` checks) [2](#0-1) . No proof-of-work, fee, or rate limiting bounds the number of distinct chains/keys a single correspondent can submit, and the reclamation mechanisms (`eventBus` event firing, hourly cache sweep) are both easily starved by an attacker who never lets the awaited unit validate.

### Recommendation
- Enforce a maximum size on `handledChainsCache` (evict oldest entries once a cap is reached, similar to `MAX_ITEMS_IN_CACHE` in `storage.js`) rather than relying solely on a 1-hour age-based sweep.
- Add an explicit timeout for each `eventBus.once(key, ...)` listener registered in the `ifQueued` branch of `handlePrivatePaymentChains`, removing the listener and associated `assocValidatedByKey` entry if the referenced unit does not validate within a bounded time window.
- Rate-limit or cap the number of concurrently pending (queued) private-payment validations per correspondent/device.

### Proof of Concept
1. As a paired device already connected to a victim wallet, repeatedly send `private_payments` messages, each containing a syntactically valid `chains` array (satisfying `isNonemptyObject`/`isNonemptyArray`/`isNonemptyString` checks) that references freshly-generated, non-existent unit hashes and unique `payload` content (to get a fresh `json_payload_hash` and thus a fresh `cache_key` per call).
2. Since the victim is acting as a light client, each chain element hits the `ifQueued` callback, immediately registering an `eventBus.once` listener and returning without blocking (`cb()` called synchronously) [9](#0-8) .
3. Never send the referenced units, so the awaited event is never emitted and the listener is never removed.
4. Repeat at high frequency; observe `eventBus` listener count and `handledChainsCache` size (and overall process memory) grow without bound over the course of an hour and beyond, since neither structure has a maximum-size cap independent of time.

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

**File:** wallet.js (L991-994)
```javascript
	var cancelAllKeys = function(){
		for (var key in assocValidatedByKey)
			eventBus.removeAllListeners(key);
	};
```

**File:** wallet.js (L1049-1063)
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
			});
```

**File:** wallet.js (L1065-1071)
```javascript
		function(err){
			bParsingComplete = true;
			if (err){
				cancelAllKeys();
				return callbacks.ifError(err);
			}
			checkIfAllValidated();
```

**File:** wallet.js (L1072-1072)
```javascript
			handledChainsCache[cache_key] = Date.now();
```

**File:** storage.js (L2250-2260)
```javascript
async function shrinkCache(){
	if (Object.keys(assocCachedAssetInfos).length > MAX_ITEMS_IN_CACHE)
		assocCachedAssetInfos = {};
	console.log(Object.keys(assocUnstableUnits).length+" unstable units");
	var arrKnownUnits = Object.keys(assocKnownUnits);
	var arrPropsUnits = Object.keys(assocCachedUnits);
	var arrStableUnits = Object.keys(assocStableUnits);
	var arrAuthorsUnits = Object.keys(assocCachedUnitAuthors);
	var arrWitnessesUnits = Object.keys(assocCachedUnitWitnesses);
	if (arrPropsUnits.length < MAX_ITEMS_IN_CACHE && arrAuthorsUnits.length < MAX_ITEMS_IN_CACHE && arrWitnessesUnits.length < MAX_ITEMS_IN_CACHE && arrKnownUnits.length < MAX_ITEMS_IN_CACHE && arrStableUnits.length < MAX_ITEMS_IN_CACHE)
		return console.log('cache is small, will not shrink');
```
