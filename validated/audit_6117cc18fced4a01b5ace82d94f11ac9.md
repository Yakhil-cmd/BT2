### Title
Unbounded `assocValidatedByKey`/eventBus listener accumulation in `handlePrivatePaymentChains` when private-payment chains never resolve — memory leak DoS (File: wallet.js)

### Summary
`wallet.js:handlePrivatePaymentChains` (invoked whenever a device/peer sends a `private_payment_chains` message) builds a `key` per private element as `'private_payment_validated-'+unit+'-'+json_payload_hash+'-'+output_index`, marks it `false` in `assocValidatedByKey`, and — for the light-client path — registers a one-shot listener `eventBus.once(key, function(bValid){...})` when `network.handleOnlinePrivatePayment` reports `ifQueued` (i.e., the chain is waiting on an unresolved parent unit).

### Finding Description
For every chain element that ends up in the `ifQueued` branch, `wallet.js` at [1](#0-0) 
registers a listener keyed by a value derived from attacker-controlled `unit`/`payload` data. That listener is only ever removed by:
1. the corresponding `key` event actually firing (emitted elsewhere once the unit is later verified/known), or
2. `cancelAllKeys()` being invoked, which iterates `assocValidatedByKey` and calls `eventBus.removeAllListeners(key)` — but only from the `err` branch of the `async.eachSeries` loop over `arrChains` [2](#0-1) .

A single unprivileged private-payment counterparty (any correspondent device, since this is reachable via `handleMessageFromHub`'s private-payment-chain handling path) can post an unbounded number of syntactically-valid chains whose head unit never resolves (e.g., an author/asset/output that legitimately queues forever because the underlying unit or asset definition is never delivered/never becomes valid, or is crafted so it always ends in `ifWaitingForChain`/`ifQueued` without ever transitioning to a resolved state). Each such call:
- Creates a new `cache_key` (`objectHash.getBase64Hash(arrChains)`), so `handledChainsCache` dedup does not prevent repeat submissions with trivially varied content.
- Leaves a permanent `eventBus.once(key, ...)` closure alive, holding references to `arrChains`, `assocValidatedByKey`, `ws`, `callbacks`, and other captured variables.
- Never triggers `cancelAllKeys()` because no `err` occurs — the flow just stays parked in `ifQueued` state indefinitely.

This mirrors the CVE-2020-25644 bug class: a normal, permitted external interaction (posting a private-payment chain / removing an HTTP session) leaves behind a per-request cache/listener entry that is never cleaned up, letting an ordinary counterparty accumulate unbounded memory over repeated requests.

### Impact Explanation
Each abandoned listener retains references to the full `arrChains` payload (which can include multiple large private elements) and various closures. An attacker who is simply a private-payment counterparty (no special privilege) can repeatedly send crafted private-payment chains that always land in the queued state, growing `eventBus`'s internal listener maps and retained payload objects without bound. Over time this exhausts process memory, causing the node/wallet process to crash or become unresponsive — a denial-of-service against normal operation (inability to process further payments/AA triggers/etc.), matching the "network unable to confirm new units" / general availability-loss class of impact this scan permits.

### Likelihood Explanation
The path is reachable by any correspondent capable of sending `private_payment_chains` device messages (a normal, unprivileged private-payment counterparty), requires no compromised keys, no special network role, and no more than repeated, valid-looking chain submissions that resolve to the `ifQueued` branch. This makes the likelihood high for any node/wallet that processes private payments from arbitrary correspondents.

### Recommendation
- Add a TTL/expiry to entries in `assocValidatedByKey`/pending listeners analogous to `handledChainsCache`'s cleanup, and actively call `eventBus.removeAllListeners(key)` (and drop cached data) once a bounded timeout elapses without resolution, regardless of whether an `err` occurred.
- Cap the number of concurrently pending "queued" private-payment listeners per peer/address, rejecting or dropping new submissions once the cap is exceeded.
- Ensure `cancelAllKeys()`-style cleanup runs on timeout, not only on validation error, so listeners tied to chains that neither succeed nor fail (perpetually queued) are still reclaimed.

### Proof of Concept
1. As a device correspondent, repeatedly call `handleMessageFromHub` with a `private_payment_chains` message whose `chains` contain a head private element referencing a unit/asset that this light node can never fully resolve (e.g., referencing an asset definition unit that is withheld/never sent, keeping `findUnfinishedPastUnitsOfPrivateChains`/`validateAndSavePrivatePaymentChain` perpetually in the `ifWaitingForChain`/`ifQueued` branch).
2. Vary a trivial field of `arrChains` each time so `objectHash.getBase64Hash(arrChains)` produces a new `cache_key`, bypassing the `handledChainsCache` short-circuit at [3](#0-2) .
3. Each submission adds new entries to `assocValidatedByKey` and a new permanent `eventBus.once(key, ...)` listener at [4](#0-3) 
that is never removed because the chain never reaches `ifError` (so `cancelAllKeys()` is never invoked) and never reaches the resolved state that would fire the `key` event.
4. Repeat at scale to observe unbounded growth of retained `arrChains` payloads and `eventBus` listener count, eventually exhausting memory.

### Citations

**File:** wallet.js (L979-983)
```javascript
	if (handledChainsCache[cache_key]) {
		eventBus.emit('all_private_payments_handled', from_address);
		eventBus.emit('all_private_payments_handled-' + arrChains[0][0].unit);
		return callbacks.ifOk();
	}
```

**File:** wallet.js (L1020-1069)
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
```
