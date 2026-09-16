### Title
Unbounded in-memory cache of private-payment chain hashes allows a paired correspondent to exhaust wallet memory - (File: wallet.js)

### Summary
`wallet.js` maintains an in-process cache, `handledChainsCache`, that records every distinct private-payment chain a wallet has processed, keyed by a hash of the chain content. Entries are only pruned once per hour, and there is no cap on the number of distinct keys that can be inserted before that sweep runs. A paired correspondent (private-payment counterparty) can flood the wallet with a large number of syntactically-valid-looking but distinct private-payment chain payloads within that hour window, growing the map without bound and exhausting memory/CPU on the receiving wallet — a resource-exhaustion pattern directly analogous to the Apache Wicket "multiple requests create unreleased request-cycle state" memory-leak DoS (CVE-2024-53299). [1](#0-0) 

### Finding Description
`handlePrivatePaymentChains` is the handler invoked when a wallet receives a `private_payments`-type device message from a correspondent (private-payment counterparty). It performs light structural validation of `body.chains` (non-empty arrays/objects with the expected fields) and then computes a hash of the whole `arrChains` structure to use as a cache key: [2](#0-1) 

After validation completes, the result is memorized forever (until the hourly sweep) in `handledChainsCache[cache_key] = Date.now()`: [3](#0-2) 

The only cleanup mechanism is a `setInterval` that runs once per hour and deletes entries older than one hour: [1](#0-0) 

There is no maximum size enforced on `handledChainsCache`, and no rate limiting on how many distinct `private_payments` messages a correspondent can send within that hour. Because the cache key is derived from `objectHash.getBase64Hash(arrChains)`, an attacker only needs to vary any field (e.g., a bogus `unit` string, output amount, or index) to produce a new, distinct key that structurally satisfies the light validation (`isNonemptyObject`, `isNonemptyArray`, presence of `unit`/`payload`/`asset`/`inputs`/`outputs` fields) — full unit validation happens later/asynchronously and does not gate whether the entry is added to the cache. Each processed chain also spins up per-key bookkeeping via `assocValidatedByKey`, `eventBus` listeners for `private_payment_validated-*`, and calls into `network.handleOnlinePrivatePayment`, multiplying the per-request memory/CPU cost well beyond just the hash-map entry.

### Impact Explanation
An attacker who is a paired correspondent (e.g., an asset issuer or any device with a valid pairing to the victim wallet, which is a normal, low-privilege trust relationship in Obyte) can repeatedly send `private_payments` messages containing distinct chain payloads. Each distinct payload grows `handledChainsCache` and triggers wallet-side processing (hashing, per-chain validation dispatch, event listener registration) without any global cap. Sustained flooding can grow memory unbounded within the hourly cleanup window, degrading or crashing the victim wallet process — a denial-of-service against the wallet/light client, consistent with CWE-400 (uncontrolled resource consumption) and the reachable-DoS class described in the Wicket advisory. This does not directly cause fund loss, double-spend, or consensus divergence, but it can render the wallet unresponsive/unable to process legitimate transactions.

### Likelihood Explanation
Likelihood is significant but bounded: the attacker must already be an accepted correspondent (paired device) of the victim wallet, which is a common relationship (e.g., any merchant/counterparty interacting with a wallet for private asset payments). No special privilege beyond pairing is required, and the structural checks on `arrChains` are cheap to satisfy with garbage data, so an attacker can cheaply generate a large volume of distinct cache keys. The one-hour cleanup window bounds worst case somewhat, but a sustained attacker sending a high message rate can still accumulate a very large cache before any entries expire.

### Recommendation
- Impose a hard upper bound on the number of entries in `handledChainsCache` (e.g., LRU eviction or a fixed capacity with FIFO/oldest-first eviction) independent of the time-based sweep.
- Rate-limit `private_payments` handling per correspondent (e.g., max distinct chains per minute/hour).
- Perform cheap validity/plausibility checks (e.g., verify referenced `unit` exists or is well-formed) before allocating cache/state for a chain, so garbage payloads are rejected before being memorized.
- Reduce the cleanup interval or make it proportional to cache size/growth rate rather than fixed at one hour.

### Proof of Concept
1. Attacker pairs a device with the victim wallet (normal pairing flow) or already exists as a correspondent.
2. Attacker repeatedly sends `private_payments` device messages to the victim, each with an `arrChains` array containing a single-element chain: `[{ unit: <random-fake-unit-string>, payload: { asset: <fake-asset>, denomination:1, outputs:[{...}], inputs:[{...}] }, output_index: 0 }]`, varying at least one byte per message (e.g., a random `unit` field) so each hashes to a unique `cache_key`.
3. Each message passes the light structural checks in `handlePrivatePaymentChains` (`isNonemptyArray`/`isNonemptyObject` checks) and is inserted into `handledChainsCache` on completion of chain validation processing, regardless of ultimate acceptance.
4. Repeat at high frequency for up to an hour; `handledChainsCache`, along with the transient per-message `assocValidatedByKey` maps and event-listener registrations, grows continuously, consuming increasing memory/CPU on the victim wallet process until performance degrades or the process crashes/OOMs.

Note: Full confirmation of end-to-end reachability (the exact `subject` string dispatched from `device.js`/`handleMessageFromHub` to `handlePrivatePaymentChains`, and whether any hub- or protocol-level rate limiting exists upstream) could not be completely verified within the available tool calls; a Devin session with full repo access is recommended to trace `eventBus.on('handle_message_from_hub', ...)` wiring in `wallet.js` and confirm the exact message subject and any missing throttling.

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

**File:** wallet.js (L1065-1078)
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
	);
```
