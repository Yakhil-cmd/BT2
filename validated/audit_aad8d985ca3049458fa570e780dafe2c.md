### Title
Improper Correlation Key in Private Payment Chain Validation Event Cache Enables Cross-Chain Result Confusion - (File: wallet.js)

### Summary
`ocore`'s private-payment validation flow correlates an asynchronous, DB-backed validation result to the in-flight caller purely through a derived string key built from `unit + hash(payload) + output_index`. This key omits `message_index`, so two distinct private-payment chains that a paired device (or the hub) delivers concurrently can be matched to the same `eventBus` key and have their validation outcomes swapped — the same bug class as the Auth0 `TokenRequestCache` advisory (GHSA-wcgj-f865-c7j7), where an under-specified cache/lookup key let one caller's result be delivered to a different, concurrent caller.

### Finding Description
When a device sends `private_payments` to the wallet, `handlePrivatePaymentChains` derives a correlation key per chain from only the head element's `unit`, a hash of its `payload`, and `output_index` (which is hard-coded to `-1` for every divisible-asset chain, regardless of the real output index): [1](#0-0) 

It then calls `network.handleOnlinePrivatePayment`, and if the result is not immediately available it registers a one-shot listener on that exact key: [2](#0-1) 

The deferred/DB-driven completion path, `handleSavedPrivatePayments`, later re-derives the *same* key formula independently (again omitting `message_index`) and emits the real validation result on it: [3](#0-2) 

Because `message_index` is not part of the key, and `output_index` collapses to a constant `-1` for divisible assets, the key's only real discriminator is `hash(payload)`. Nothing in this path enforces that two different messages/chains delivered concurrently for the same head `unit` must have different payloads — e.g. a malicious or buggy counterparty can send two chains that share the same head `unit` and an identical `payload` (same asset/inputs/outputs) as two different messages (`message_index`) in that unit, or simply replay/duplicate a chain concurrently with a legitimate one. When that happens, `eventBus.emit(key, true/false)` fires for **one** underlying validation, but is delivered to **every** listener registered under that same key string — including the listener belonging to the *other*, unrelated chain that is still separately being validated. This lets a validation success (`true`) for chain A spuriously satisfy `assocValidatedByKey[key]` for chain B in a concurrent `handlePrivatePaymentChains` call, even though chain B's own DB-backed validation in `handleSavedPrivatePayments`/`private_payment.js` never actually confirmed it — or is still pending/failing.

### Impact Explanation
`checkIfAllValidated` treats a chain as validated purely based on this cross-wired event firing: [4](#0-3) 
and, once satisfied, the wallet proceeds to treat the private payment as accepted, notify the user of a received payment, and forward the (unverified) chain to other members of shared/output addresses. A counterparty controlling the content of concurrent private-payment deliveries can therefore cause the wallet to believe an unvalidated/forged private chain was accepted, leading to funds being credited/forwarded without genuine per-chain validation — a private-payment acceptance bypass reachable by any private-payment counterparty or paired device, matching the "concrete unauthorized spending"/fund-loss impact bar.

### Likelihood Explanation
The attacker only needs to be a normal private-payment counterparty capable of sending crafted/duplicated `private_payments` messages through the hub (or directly) so that two chains referencing the same head `unit` and identical `payload` bytes are processed concurrently — no privileged network position, malicious node, or protocol downgrade is required. The narrow input surface (`payload` equality plus a constant `-1` for divisible-asset `output_index`) makes deliberate collision crafting feasible for the payload's own author (the issuer/sender who controls its exact bytes).

### Recommendation
Include `message_index` (and the true `output_index`, not a divisible-collapsed `-1`) in the correlation key used in both `wallet.js`'s `handlePrivatePaymentChains` and `network.js`'s `handleSavedPrivatePayments`, so the key uniquely identifies the specific message/output being validated rather than relying solely on payload-hash equality.

### Proof of Concept
1. Attacker (a paired device / private-payment counterparty) constructs a unit containing two payment messages (`message_index` 0 and 1) for the same private/divisible asset whose `payload` (asset, inputs, outputs, blinding) is byte-identical, or otherwise arranges for two concurrently-delivered private chains referencing the same head `unit` to hash to the same `payload`.
2. Sends both corresponding private-payment chains to the victim wallet in quick succession (or via two overlapping hub deliveries), so both hit `handlePrivatePaymentChains` and register `eventBus.once(key, ...)` under the identical key computed at `wallet.js:1033`.
3. When `handleSavedPrivatePayments` finishes real validation for one of the two DB rows and emits `eventBus.emit(key, true)` at `network.js:2488`, both listeners fire, marking the second (unvalidated/forged) chain as validated too.
4. The wallet's `checkIfAllValidated` accepts and forwards/credits the second chain despite it never passing its own independent DB validation.

### Citations

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

**File:** wallet.js (L1026-1034)
```javascript
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

**File:** network.js (L2467-2496)
```javascript
					var validateAndSave = function(){
						var objHeadPrivateElement = arrPrivateElements[0];
						try {
							var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
						}
						catch (e) {
							console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
							if (ws)
								sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
							deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
						}
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
```
