### Title
Unbounded private-payment chains cause unlimited memory/storage growth without validation limits - (File: network.js, wallet.js)

### Summary
`handleOnlinePrivatePayment` in `network.js` and `handlePrivatePaymentChains` in `wallet.js` accept an attacker-controlled array of private-payment "chains" (`arrPrivateElements`/`arrChains`) sent as a `justsaying` message (`private_payment`) or via a paired-device message (`private_payment_chains` subject), and persist them to the `unhandled_private_payments` table with no bound on the number of elements per chain, the number of chains, or the size of each element's JSON payload, before any of the size/complexity limits that `validation.js` enforces on ordinary units (`MAX_UNIT_LENGTH`, `MAX_MESSAGES_PER_UNIT`, `isTooDeeplyNestedOrHasTooManyNodes`, etc.) are ever applied.

### Finding Description
`handleOnlinePrivatePayment` only checks that `arrPrivateElements` is a non-empty array and that the head element's `unit`, `message_index` and `output_index` fields have the right type/format: [1](#0-0) 
When the referenced unit is not yet known (`ifNew`) or not yet verified (`ifKnownUnverified`), the whole chain is serialized with `JSON.stringify(arrPrivateElements)` and stored in the `unhandled_private_payments` table: [2](#0-1) 
No limit is imposed here on `arrPrivateElements.length` (chain length) nor on the size of the objects inside it (e.g. `payload.outputs`), unlike normal unit validation in `validation.js`, which enforces `MAX_UNIT_LENGTH`, `MAX_MESSAGES_PER_UNIT`, and `isTooDeeplyNestedOrHasTooManyNodes` before accepting a unit into memory/DB: [3](#0-2) [4](#0-3) 

On the wallet side, `handlePrivatePaymentChains` in `wallet.js`, reachable from a paired device (private-payment counterparty) via a hub-relayed message, validates only the *shape* of each chain element (non-empty objects/strings) — not the number of chains, the length of each chain, or overall payload size — and then feeds every chain into `network.handleOnlinePrivatePayment`: [5](#0-4) [6](#0-5) 
For light wallets, receiving a chain whose length is greater than 1 additionally triggers `updateLinkProofsOfPrivateChain`/`rerequestLostJointsOfPrivatePayments`, meaning the attacker can keep the chain "unfinished" indefinitely (like an OPC-UA chunk sequence that never sends the Final flag) while the head record still occupies a `unhandled_private_payments` row and drives repeated background processing (`handleSavedPrivatePayments`) each time new units arrive: [7](#0-6) [8](#0-7) 

This mirrors the root cause of CVE-2022-25761: an actor can submit an unbounded number of "chunks" (private-payment chain elements) that are individually accepted and buffered without ever completing/being finalized, and without any global or per-session size cap, exhausting node memory/DB storage.

### Impact Explanation
A malicious paired device (wallet counterparty) or hub-relayed peer can repeatedly send `private_payment`/`private_payment_chains` messages containing large numbers of chains and/or long chains (deeply nested arrays of fake `payload.outputs`/`inputs`), each of which is JSON-stringified and stored via `INSERT ... INTO unhandled_private_payments`. Because this path is exempt from the unit-level size/complexity guards (`MAX_UNIT_LENGTH`, `MAX_MESSAGES_PER_UNIT`, `isTooDeeplyNestedOrHasTooManyNodes`) that protect ordinary joints, the victim node's database and/or process memory can grow without bound, degrading or crashing the node — a Denial-of-Service condition preventing the node from confirming new units, consistent with High severity network availability impact.

### Likelihood Explanation
The `private_payment`/`private_payment_chains` message paths are reachable by any paired device or private-payment counterparty without requiring privileged/hub/operator access — a normal wallet-to-wallet interaction. No authentication beyond the paired-device channel is required, and no rate limiting or size cap exists on `arrPrivateElements`/`arrChains` before persistence, making exploitation straightforward for anyone who can pair with or relay through a victim's hub.

### Recommendation
Enforce hard limits before accepting/persisting private-payment chains:
- Cap `arrPrivateElements.length` (chain length) and `arrChains.length` (number of chains per message) to reasonable values (e.g., comparable to `MAX_MESSAGES_PER_UNIT`).
- Apply `isTooDeeplyNestedOrHasTooManyNodes`/`isTooBigObj`-style checks (already used in `validation.js` and `string_utils.js`) to `arrPrivateElements`/`arrChains` before `JSON.stringify` and DB insertion.
- Add a per-device/per-peer quota or rate limit on the number of unresolved rows a single source can create in `unhandled_private_payments`, and purge/expire stale unfinished chains.

### Proof of Concept
1. Establish (or simulate) a paired-device relationship or a direct peer connection to a victim ocore node.
2. Send repeated `justsaying` messages with subject `private_payment` (via `network.js`'s `handleOnlinePrivatePayment` entry point) or `private_payment_chains` (via `wallet.js`'s `handlePrivatePaymentChains`), each containing an `arrChains`/`arrPrivateElements` array with thousands of large synthetic elements (deeply nested `payload.outputs`/`inputs`) referencing a unit that is not yet known (`ifNew`) so it is always queued via `savePrivatePayment`.
3. Observe unbounded growth of the `unhandled_private_payments` table (`JSON.stringify(arrPrivateElements)` size × count) and repeated re-processing overhead in `handleSavedPrivatePayments`, exhausting node storage/memory over time — since no path validates cumulative size or chain length before persistence.

### Citations

**File:** network.js (L2376-2389)
```javascript
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
	if (!ValidationUtils.isValidBase64(unit, constants.HASH_LENGTH))
		return callbacks.ifError("invalid unit");
	if (!ValidationUtils.isNonnegativeInteger(message_index))
		return callbacks.ifError("invalid message_index");
	if (!(ValidationUtils.isNonnegativeInteger(output_index) || output_index === -1))
		return callbacks.ifError("invalid output_index");

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

**File:** network.js (L2444-2521)
```javascript
function handleSavedPrivatePayments(unit){
	//if (unit && assocUnitsInWork[unit])
	//    return;
	if (!my_device_address) return; // skip if we don't have a wallet
	if (!unit && mutex.isAnyOfKeysLocked(["private_chains"])) // we are still downloading the history (light)
		return console.log("skipping handleSavedPrivatePayments because history download is still under way");
	var lock = unit ? mutex.lock : mutex.lockOrSkip;
	lock(["saved_private"], function(unlock){
		var sql = unit
			? "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments WHERE unit="+db.escape(unit)
			: "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments CROSS JOIN units USING(unit)";
		db.query(sql, function(rows){
			if (rows.length === 0)
				return unlock();
			var assocNewUnits = {};
			async.each( // handle different chains in parallel
				rows,
				function(row, cb){
					var arrPrivateElements = JSON.parse(row.json);
					var ws = getPeerWebSocket(row.peer);
					if (ws && ws.readyState !== ws.OPEN)
						ws = null;
					
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
							},
							// light only. Means that chain joints (excluding the head) not downloaded yet or not stable yet
							ifWaitingForChain: function(){
								console.log('waiting for chain: unit '+row.unit+', message '+row.message_index+' output '+row.output_index);
								cb();
							}
						});
					};
					
					if (conf.bLight && arrPrivateElements.length > 1 && !row.linked)
						updateLinkProofsOfPrivateChain(arrPrivateElements, row.unit, row.message_index, row.output_index, cb, validateAndSave);
					else
						validateAndSave();
					
				},
				function(){
					unlock();
					var arrNewUnits = Object.keys(assocNewUnits);
					if (arrNewUnits.length > 0)
						eventBus.emit("new_my_transactions", arrNewUnits);
				}
			);
		});
	});
}
```

**File:** validation.js (L154-156)
```javascript
	if (isTooDeeplyNestedOrHasTooManyNodes(objUnit))
		return bAA ? callbacks.ifUnitError("unit is too deeply nested") : callbacks.ifJointError("unit is too deeply nested");

```

**File:** validation.js (L212-217)
```javascript
		if (!isNonemptyArray(objUnit.messages))
			return callbacks.ifUnitError("missing or empty messages array");
		if (objUnit.messages.length > constants.MAX_MESSAGES_PER_UNIT && !bGenesis)
			return callbacks.ifUnitError("too many messages");
		if (!objUnit.messages.every(isNonemptyObject))
			return callbacks.ifUnitError("all messages must be non-empty objects");
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

**File:** wallet.js (L1020-1064)
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
```
