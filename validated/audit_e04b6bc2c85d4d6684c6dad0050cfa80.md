## Title
Unbounded private-payment chain arrays in `handlePrivatePaymentChains` allow memory-exhaustion DoS by a paired device — ([File: wallet.js])

### Summary
The CVE describes an OpenEXR scanline parser that trusts attacker-supplied size/count fields when allocating buffers, letting a crafted file exhaust memory. The analog in this codebase is `handlePrivatePaymentChains` in `wallet.js`, which accepts a `private_payment_chain` device message from *any paired correspondent device* and processes the entire `body.chains` array — an array of arrays of private-payment elements — with no limit on the number of chains or the length of each chain before doing per-element JSON hashing, DB writes, and recursive forwarding work.

### Finding Description
`handlePrivatePaymentChains(ws, body, from_address, callbacks)` reads `arrChains = body.chains` and only validates that it is a non-empty array whose elements are non-empty objects/arrays with the expected string fields — there is no cap on `arrChains.length` or on the length of each inner chain `c` before the function proceeds: [1](#0-0) 

After this superficial shape check, the code computes a hash of the whole `arrChains` structure and then iterates every chain with `async.eachSeries`, building an `assocValidatedByKey` entry for each and calling `network.handleOnlinePrivatePayment` for every one: [2](#0-1) 

For light clients (`conf.bLight` true, the normal wallet mode reachable by an unprivileged paired device / private-payment counterparty), `network.handleOnlinePrivatePayment` immediately persists the *entire unvalidated* chain into the `unhandled_private_payments` table as a JSON blob before any real validation occurs, and for chains longer than one element it schedules additional link-proof requests: [3](#0-2) 

Later, `handleSavedPrivatePayments` re-parses every stored JSON blob back into memory (`JSON.parse(row.json)`) for processing: [4](#0-3) 

Neither `constants.js` nor `wallet.js`/`network.js`/`private_payment.js` define any `MAX_*` limit on the number of chains per message, the number of elements per chain, or the total serialized size of `body.chains`/`arrPrivateElements` — a grep for chain-size constants across the repo returns no hits outside of unrelated `catchup.js` chain-length checks. Compare this to the unit-level protections that do exist elsewhere (e.g. `constants.MAX_UNIT_LENGTH`, `constants.MAX_DENOMINATIONS_PER_ASSET_DEFINITION`, and AA formula `isTooBigObj`/array-literal-length checks in `formula/evaluation.js`) — private payment chains from a paired device lack an equivalent bound.

### Impact Explanation
A malicious paired device (or a device impersonating one through a hub, since `bViaHub` messages skip peer-address checks) can send a single `private_payment_chain` message containing an extremely large `chains` array, or chains with an extremely large number of elements/outputs each. This causes:
- A large `JSON.stringify`/hash computation over the full structure up front (`objectHash.getBase64Hash(arrChains)`), and per-element `objectHash.getBase64Hash` calls in the loop.
- Bulk unvalidated JSON persisted into `unhandled_private_payments` for light clients, then re-parsed into memory in `handleSavedPrivatePayments`.
- `async.eachSeries` iterating unboundedly many chains, each spinning up further asynchronous DB work and event-bus listeners (`assocValidatedByKey`), and forwarding logic (`forwardPrivateChainsToOtherMembersOfOutputAddresses`) that itself expands the address set and touches more wallets.

This matches the CVSS 3.1 profile of the CVE (local/network low-complexity, no privileges beyond being a correspondent, user interaction via message receipt, availability impact only) — the risk here is a wallet/hub process being driven into excessive memory/CPU consumption ("a network unable to confirm new units" / node degradation), satisfying the rule's "no impact" exclusion is avoided because it can crash or stall a node's wallet component processing legitimate future private payments.

### Likelihood Explanation
Likelihood is high for any node that runs the wallet layer and accepts messages from paired devices/hub-relayed correspondents (this is standard operation for any Obyte wallet, not an operator-only or admin path). No signature or proof-of-work is required to send a `private_payment_chain` message — only correspondent pairing, which is the normal flow for anyone who has ever exchanged a pairing link with the victim, or via a malicious/compromised hub relaying `bViaHub` traffic.

### Recommendation
Add explicit bounds before processing, mirroring existing unit-level protections:
- Reject `body.chains` if `arrChains.length` exceeds a new `constants.MAX_PRIVATE_CHAINS_PER_MESSAGE`.
- Reject any individual chain `c` if `c.length` exceeds a new `constants.MAX_PRIVATE_CHAIN_LENGTH`.
- Bound the total serialized size of `body.chains` (e.g., via `object_length.getLength`) before hashing/storing it, similar to `constants.MAX_UNIT_LENGTH` for units.
- Apply the same limits inside `network.handleOnlinePrivatePayment`/`handleSavedPrivatePayments` before persisting/parsing the JSON blob, so a queued/light-client path can't bypass the check.

### Proof of Concept
1. Pair a malicious device with a victim wallet (or relay via a malicious/controlled hub using `bViaHub`).
2. Send a `private_payment_chain` message where `body.chains` is an array of, e.g., 100,000 synthetic chain arrays, each containing a chain of many elements with valid-looking but ultimately invalid `unit`/`payload` fields sufficient to pass the shallow `isNonemptyObject`/`isNonemptyString` checks in lines 959–972 of `wallet.js`.
3. Observe that `handlePrivatePaymentChains` accepts the shape check, computes `objectHash.getBase64Hash(arrChains)` over the entire structure, and (for light clients) writes the full JSON into `unhandled_private_payments` and iterates the chains via `async.eachSeries`, consuming memory/CPU proportional to the attacker-chosen size with no upper bound enforced anywhere in the call path.

### Citations

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

**File:** wallet.js (L973-1022)
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
	profiler.increment();
	
	if (conf.bLight)
		network.requestUnfinishedPastUnitsOfPrivateChains(arrChains); // it'll work in the background
	
	var assocValidatedByKey = {};
	var bParsingComplete = false;
	var cancelAllKeys = function(){
		for (var key in assocValidatedByKey)
			eventBus.removeAllListeners(key);
	};

	var current_message_counter = ++message_counter;

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
	
	async.eachSeries(
		arrChains,
		function(arrPrivateElements, cb){ // validate each chain individually
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

**File:** network.js (L2461-2462)
```javascript
				function(row, cb){
					var arrPrivateElements = JSON.parse(row.json);
```
