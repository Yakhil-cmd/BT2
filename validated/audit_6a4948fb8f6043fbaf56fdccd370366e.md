### Title
Unbounded Growth of `handledChainsCache` Enables Memory-Exhaustion DoS via Crafted Private Payment Chains - (File: wallet.js)

### Summary
`wallet.js` maintains a process-wide cache, `handledChainsCache`, keyed by the hash of an entire private-payment chain array, that is populated whenever `handlePrivatePaymentChains()` processes a `private_payments` message from a paired device or private-payment counterparty. The cache has no size limit and is pruned only once per hour, and only for entries already older than one hour. Because the cache key is derived from attacker-controlled chain content and an entry is written as soon as chain elements pass structural checks and are queued for later validation (not necessarily fully validated), a remote peer can cheaply generate an unbounded number of distinct, well-formed-but-otherwise-meaningless chains and force the process to retain a growing, unbounded in-memory cache until `OutOfMemoryError`/crash — the same bug class as the Keycloak JWT-cache DoS (CWE-770, uncontrolled resource consumption from an attacker-influenced cache with no eviction bound).

### Finding Description
`handledChainsCache` is declared with an hourly sweep that removes only entries older than an hour: [1](#0-0) 

`handlePrivatePaymentChains(ws, body, from_address, callbacks)` is the entry point reached from any paired device / hub message of type `private_payments`. It computes `cache_key = objectHash.getBase64Hash(arrChains)` from the attacker-supplied `body.chains`, and short-circuits if that exact key was already seen: [2](#0-1) 

The only structural validation performed before this point is a shallow shape check (`isNonemptyArray`, `isNonemptyObject`, presence of `unit`/`payload`/`inputs`/`outputs` fields) — it does not require the referenced `unit` to exist, be valid, or be signed: [3](#0-2) 

After iterating the chains, the completion callback of `async.eachSeries` unconditionally stores the new cache key with a timestamp as long as no chain synchronously errored — including the common `ifQueued` outcome (typical for light clients when referencing not-yet-known units), where full validation only completes later asynchronously via `eventBus.once(key, ...)`: [4](#0-3) 

Because `cache_key` is a hash of the entire (attacker-chosen) `arrChains` payload, trivially varying any field (amount, fake unit id, address, payload contents) produces a new, unique key. Each such variant that merely passes the shallow shape check and reaches the "queued" branch adds a new permanent entry to `handledChainsCache` holding a numeric timestamp, with no cap on the number of distinct keys and no bound on how large the cache can grow between hourly sweeps (and the sweep does not evict entries younger than one hour, so a sustained request rate keeps the cache growing indefinitely). This directly mirrors the Keycloak flaw: a cache populated from attacker-controlled, cheaply-produced inputs, evicted only by a time-based sweep, with no overall size limit — enabling unbounded memory growth and eventual `OutOfMemoryError`/DoS.

### Impact Explanation
An attacker who can reach a wallet's message handler (a paired device, a private-payment counterparty, or anyone routed through a hub to a light wallet) can send a continuous stream of syntactically-valid-but-otherwise-junk `private_payments` messages. Each unique payload produces a new, permanent (for at least one hour) entry in `handledChainsCache`. Sustained at any nontrivial rate, this can exhaust process memory faster than the hourly sweep can reclaim it, crashing the wallet/light node process — a denial of service against a node that should otherwise be able to keep servicing legitimate private payments and confirm new units. This satisfies the "network unable to confirm new units" / node-DoS impact bar for an unprivileged, remotely reachable code path (paired device / private-payment counterparty), analogous to the original Keycloak CVE.

### Likelihood Explanation
Likelihood is high for any wallet or light client that accepts private-payment chains from correspondents/paired devices, since:
- No authentication beyond an existing device pairing or hub routing is required.
- The shallow validation performed before the cache write is cheap for the attacker to satisfy (basic object/array shape).
- Generating unique cache keys is trivial (vary any field in the chain payload).
- The cache has no explicit maximum size — growth is bounded only by available memory and the passive one-hour sweep.

### Recommendation
- Cap `handledChainsCache` to a fixed maximum number of entries (e.g., LRU eviction), independent of time-based expiry.
- Do not populate the cache until a chain is fully validated (`ifAccepted`/final `bValid` from the queued path), not merely queued.
- Rate-limit or size-limit the number of distinct `private_payments` requests processed per correspondent/device within a time window before they reach `handlePrivatePaymentChains`.
- Consider hashing/storing a bounded proxy (e.g., only the head unit + output index) rather than the entire chain content, and evict based on both age and total memory/entry-count budget.

### Proof of Concept
1. Establish (or use an existing) device-pairing / hub relationship so `handlePrivatePaymentChains` is reachable (this is the normal path for exchanging private payments between wallets).
2. Repeatedly send `private_payments` messages whose `body.chains` are syntactically valid (satisfy `isNonemptyObject`/`isNonemptyString`/`isNonemptyArray` checks in [5](#0-4)  but reference unit ids/amounts that are unique each time and not locally known, so `network.handleOnlinePrivatePayment` routes them to `ifQueued`.
3. Each such message computes a unique `cache_key = objectHash.getBase64Hash(arrChains)` and, once the synchronous phase of `async.eachSeries` completes without a synchronous error, is written into `handledChainsCache` in the completion callback [6](#0-5) .
4. Repeating step 2 at a sustained rate causes `handledChainsCache` to grow without bound (only entries older than 1 hour are purged, once per hour, per [1](#0-0) ), eventually exhausting process memory.

Note: I was unable to fully trace `network.handleOnlinePrivatePayment`'s exact conditions for choosing `ifQueued` vs `ifValidationError` (the function body itself was not retrieved before the tool budget ran out), so the precise cost/effort an attacker needs to reliably land in the `ifQueued` branch at scale is not fully confirmed from the indexed code — a Devin session with full file access should verify this function in `network.js` to confirm the exact PoC trigger conditions.

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

**File:** wallet.js (L955-983)
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
```

**File:** wallet.js (L1049-1078)
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
