### Title
Unbounded memory growth from never-resolved private-payment validation trackers - (File: wallet.js)

### Summary
`handlePrivatePaymentChains` in [1](#0-0)  registers per-chain tracking state (`assocValidatedByKey[key] = false`) and, when validation is queued rather than immediate, an `eventBus.once(key, ...)` listener, for every private-payment chain a paired device sends it. Analogous to CVE-2020-29485 (oxenstored not freeing all watch-tracking state on `XS_RESET_WATCHES`, letting a guest grow memory unboundedly), this code creates tracking entries and event listeners keyed by a hash derived from attacker-controlled data (`unit`, `payload`, `output_index`) but only cleans them up (`cancelAllKeys()` / resolving `assocValidatedByKey`) if the corresponding `key` event is eventually emitted elsewhere. If validation never completes for the underlying unit (e.g., it is queued waiting on a dependency/parent unit that a malicious counterparty never actually delivers), the entry in `assocValidatedByKey` and the `eventBus.once(key, ...)` listener are never removed.

### Finding Description
In `handlePrivatePaymentChains` [1](#0-0) , for every chain in the incoming `body.chains` array a unique `key` is derived from `objHeadPrivateElement.unit`, the JSON hash of its payload, and `output_index` [2](#0-1) . This key is inserted into `assocValidatedByKey` and, on the `ifQueued` code path, an `eventBus.once(key, ...)` listener is registered [3](#0-2) .

The cleanup (`cancelAllKeys`) only runs in two situations: (1) `async.eachSeries` overall reports an error before parsing completes [4](#0-3) , or (2) the `key` event is eventually emitted with `bValid=false` [5](#0-4) . There is no timeout or bound on how long a queued chain can remain unresolved. A remote paired device (private-payment counterparty) can repeatedly send `private_payments` messages whose head unit references content that is accepted into the "queued" state (e.g. a unit that depends on a parent that is deliberately withheld, or crafted so that resolution is deferred indefinitely) without ever triggering the `private_payment_validated-...` event that would clear the tracker. Each such message leaves behind: a permanent object property in a closure-scoped `assocValidatedByKey` map that is never garbage collected because it's referenced by the pending `eventBus.once` closure, and a permanently registered listener on the shared, singleton `eventBus` [6](#0-5) . Because the key includes the payload hash and an attacker-chosen `unit`/`output_index`, an unlimited number of distinct keys/listeners can be generated cheaply from a single attacker-controlled device connection, exactly analogous to the Xen bug class: per-request tracking structures that are not guaranteed to be fully freed and thus accumulate without bound.

### Impact Explanation
This is a node-local unbounded memory growth vector similar in class to the CVE: the wallet/hub process handling private payments from a paired device can be driven to accumulate ever-growing `assocValidatedByKey` maps and `eventBus` listener registrations, degrading and eventually crashing the node (denial of service against normal operation, potentially disrupting the node's ability to keep processing private payments and other business as usual). It does not directly cause double-spend or fund loss but can lead to node-level DoS, consistent with the "network unable to confirm new units" / resource-based analog outcomes.

### Likelihood Explanation
Reachable by any paired device engaging in the standard private-payment protocol; no privileged access to the hub/node is required beyond having a device pairing. Triggering repeated non-resolving `ifQueued` outcomes (e.g. by referencing a chain of units whose earlier dependencies are withheld or crafted to never validate) is plausible given the asynchronous queuing design, though full confirmation of a specific "never resolves" trigger would require deeper tracing of `joint_storage`/`network.js` handling of queued private payments (not fully explored here).

### Recommendation
Bound the lifetime of `assocValidatedByKey` entries and their associated `eventBus` listeners with a timeout that force-cancels and cleans up (calls `cancelAllKeys()`-equivalent logic and deletes the eventBus listener) if a `key` never resolves within a reasonable window. Additionally, cap the number of concurrently pending validation keys per device/session to prevent a single peer from generating unbounded tracking state.

### Proof of Concept
1. Pair a malicious device with a victim wallet/hub node.
2. Send a `private_payments` message with `chains` containing a head private element whose `unit` references a joint that is deliberately never fully delivered/resolved (so `network.handleOnlinePrivatePayment` invokes `ifQueued` rather than `ifAccepted`/`ifError`).
3. Repeat with new random/distinct `payload` values (changing the computed `json_payload_hash`) to generate new, distinct `key`s each time.
4. Observe that each call adds a permanent entry into the closure-local `assocValidatedByKey` and a permanent `eventBus.once(key, ...)` listener that is never invoked or removed, since the underlying unit is never resolved—memory and listener count grow without bound over repeated messages.

### Citations

**File:** wallet.js (L955-994)
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
	
	if (conf.bLight)
		network.requestUnfinishedPastUnitsOfPrivateChains(arrChains); // it'll work in the background
	
	var assocValidatedByKey = {};
	var bParsingComplete = false;
	var cancelAllKeys = function(){
		for (var key in assocValidatedByKey)
			eventBus.removeAllListeners(key);
	};
```

**File:** wallet.js (L1027-1034)
```javascript
			try {
				var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
			}
			catch (e) {
				return cb("head priv element hash failed " + e.toString());
			}
			var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+output_index;
			assocValidatedByKey[key] = false;
```

**File:** wallet.js (L1050-1062)
```javascript
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

**File:** event_bus.js (L1-10)
```javascript
/*jslint node: true */
"use strict";
require('./enforce_singleton.js');

var EventEmitter = require('events').EventEmitter;

var eventEmitter = new EventEmitter();
eventEmitter.setMaxListeners(40);

module.exports = eventEmitter;
```
