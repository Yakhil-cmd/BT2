No size cap (`MAX_...CHAIN...` or similar) exists anywhere in `constants.js` for private-payment chains, confirming that `handlePrivatePaymentChains` has no upper bound on the number of chains or elements per chain that a correspondent device may send.

### Title
Unbounded private-payment chain processing allows resource-exhaustion DoS from a paired device - (File: wallet.js)

### Summary
`handlePrivatePaymentChains` in `wallet.js` accepts a `private_payments` device message from any correspondent (paired device) and validates only the *shape* of the data, never its *size*. Unlike ordinary unit validation, which caps message/author/output counts (`MAX_MESSAGES_PER_UNIT`, `MAX_AUTHORS_PER_UNIT`, etc.), there is no limit on `body.chains.length` or on the length of each individual chain, and no limit like `MAX_PRIVATE_CHAIN_LENGTH` exists in `constants.js`. This mirrors the Mattermost GIF-DoS bug class: a crafted, oversized-but-structurally-valid input is accepted for processing without a resource bound, letting an authenticated-but-untrusted party trigger disproportionate CPU/DB work on the victim node.

### Finding Description
`handlePrivatePaymentChains(ws, body, from_address, callbacks)` [1](#0-0)  only checks that `arrChains` is a non-empty array and that each chain element has the expected fields (`isNonemptyObject`, `isNonemptyString`, etc.). It never checks `arrChains.length` or `c.length` against any maximum.

The function then:
- computes `objectHash.getBase64Hash(arrChains)` over the entire (potentially huge) structure [2](#0-1) ;
- iterates every chain with `async.eachSeries`, and for each one calls `network.handleOnlinePrivatePayment`, which persists the raw JSON of the chain into `unhandled_private_payments` and eventually calls `privatePayment.validateAndSavePrivatePaymentChain` [3](#0-2) [4](#0-3) ;
- for each chain, `parsePrivatePaymentChain`/`validatePrivatePayment` walks every element sequentially, issuing multiple DB queries per element (spend-proof lookup, source-output inclusion check, payment validation) [5](#0-4) [6](#0-5) .

Because none of these steps enforce a maximum chain count or chain length, a correspondent (a device that is already paired via the normal pairing flow — an explicitly in-scope actor per the wallet/device message-handling surface) can submit a `private_payments` message containing an extremely large number of chains, or extremely long chains, each with many inputs/outputs. The victim wallet will then perform proportionally large hashing, JSON parsing/stringifying, and serial DB query workloads on a single incoming message, blocking or heavily degrading the wallet process — the same "insufficiently bounded processing of an accepted but crafted payload" pattern as the Mattermost GIF report (CWE-400/434 style resource exhaustion via unchecked user-supplied content).

By contrast, comparable network-facing structures (units) are explicitly bounded, e.g. `objUnit.messages.length > constants.MAX_MESSAGES_PER_UNIT` [7](#0-6) , and formula/AA evaluation has explicit complexity/op/size ceilings (`MAX_COMPLEXITY`, `MAX_OPS`, `isTooBigObj`) [8](#0-7) [9](#0-8) . No analogous cap exists for private-payment chains.

### Impact Explanation
A paired correspondent device can force a victim wallet node to spend excessive CPU and perform an unbounded number of sequential DB operations processing a single crafted `private_payments` message, degrading or freezing that wallet's ability to process legitimate traffic — a server-side Denial of Service consistent with "a network unable to confirm/process new units/payments" for the affected node. It does not directly cause double-spend or fund loss, but it can disrupt normal wallet operation for the target user, which is the closest ocore-reachable analog to the reported GIF-processing DoS.

### Likelihood Explanation
Requires only an existing device pairing (a "private-payment counterparty" relationship), which is explicitly within the allowed reach in this scan's scope. No special privileges beyond pairing are needed to send a `private_payments` justsaying/message; the attacker fully controls `body.chains` content and size before sending it.

### Recommendation
Enforce explicit limits in `handlePrivatePaymentChains` (and the underlying `validateAndSave*PrivatePaymentChain` functions) analogous to `MAX_MESSAGES_PER_UNIT`/`MAX_AUTHORS_PER_UNIT`: cap `arrChains.length`, cap the length of each individual chain, and cap payload sizes (inputs/outputs count) before beginning any hashing, JSON operations, or DB validation work, rejecting oversized payloads immediately.

### Proof of Concept
A paired correspondent device sends a `private_payments` message whose `body.chains` field is a very large array (e.g., tens of thousands of syntactically-valid minimal chain elements) or contains chains with very many elements. `handlePrivatePaymentChains` passes the shape checks (`isNonemptyArray`/`isNonemptyObject` checks only) [10](#0-9) , then proceeds to hash the whole structure and sequentially validate every element against the DB [3](#0-2) , consuming disproportionate CPU/DB time on the receiving wallet with no rejection based on size.

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

**File:** wallet.js (L973-978)
```javascript
	try {
		var cache_key = objectHash.getBase64Hash(arrChains);
	}
	catch (e) {
		return callbacks.ifError("chains hash failed: " + e.toString());		
	}
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

**File:** network.js (L2375-2441)
```javascript
// handles one private payload and its chain
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

	joint_storage.checkIfNewUnit(unit, {
		ifKnown: function(){
			//assocUnitsInWork[unit] = true;
			privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
				ifOk: function(){
					//delete assocUnitsInWork[unit];
					callbacks.ifAccepted(unit);
					eventBus.emit("new_my_transactions", [unit]);
				},
				ifError: function(error){
					//delete assocUnitsInWork[unit];
					callbacks.ifValidationError(unit, error);
				},
				ifWaitingForChain: function(){
					savePrivatePayment();
				}
			});
		},
		ifNew: function(){
			savePrivatePayment();
			// if received via hub, I'm requesting from the same hub, thus telling the hub that this unit contains a private payment for me.
			// It would be better to request missing joints from somebody else
			requestNewMissingJoints(ws, [unit]);
		},
		ifKnownUnverified: savePrivatePayment,
		ifKnownBad: function(){
			callbacks.ifValidationError(unit, "known bad");
		}
	});
}
```

**File:** indivisible_asset.js (L20-52)
```javascript
function validatePrivatePayment(conn, objPrivateElement, objPrevPrivateElement, callbacks){
		
	function validateSpendProof(spend_proof, cb){
		profiler.start();
		conn.query(
			"SELECT spend_proof, address FROM spend_proofs WHERE unit=? AND message_index=?", 
			[objPrivateElement.unit, objPrivateElement.message_index], 
			function(rows){
				profiler.stop('spend_proof');
				if (rows.length !== 1)
					return cb("expected 1 spend proof, found "+rows.length);
				var stored_spend_proof = rows[0].spend_proof;
				var spend_proof_address = rows[0].address;
				if (stored_spend_proof !== spend_proof)
					return cb("spend proof doesn't match");
				if (objPrevPrivateElement && objPrevPrivateElement.output.address !== spend_proof_address)
					return cb("spend proof address does not match src output");
				if (input.address && input.address !== spend_proof_address)
					return cb("spend proof address does not match issuer address");
				cb();
			}
		);
	}
	
	function validateSourceOutput(cb){
		if (conf.bLight)
			return cb(); // already validated the linkproof
		profiler.start();
		graph.determineIfIncluded(conn, input.unit, [objPrivateElement.unit], function(bIncluded){
			profiler.stop('determineIfIncluded');
			bIncluded ? cb() : cb("input unit not included");
		});
	}
```

**File:** indivisible_asset.js (L186-236)
```javascript
// arrPrivateElements is ordered in reverse chronological order
function parsePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	var bAllStable = true;
	var issuePrivateElement = arrPrivateElements[arrPrivateElements.length-1];
	if (!issuePrivateElement.payload || !issuePrivateElement.payload.inputs || !issuePrivateElement.payload.inputs[0])
		return callbacks.ifError("invalid issue private element");
	var asset = issuePrivateElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in issue private element");
	var denomination = issuePrivateElement.payload.denomination;
	if (!denomination)
		return callbacks.ifError("no denomination in issue private element");
	async.forEachOfSeries(
		arrPrivateElements,
		function(objPrivateElement, i, cb){
			if (!objPrivateElement.payload || !objPrivateElement.payload.inputs || !objPrivateElement.payload.inputs[0])
				return cb("invalid payload");
			if (!objPrivateElement.output)
				return cb("no output in private element");
			if (objPrivateElement.payload.asset !== asset)
				return cb("private element has a different asset");
			if (objPrivateElement.payload.denomination !== denomination)
				return cb("private element has a different denomination");
			var prevElement = null; 
			if (i+1 < arrPrivateElements.length){ // excluding issue transaction
				var prevElement = arrPrivateElements[i+1];
				if (prevElement.unit !== objPrivateElement.payload.inputs[0].unit)
					return cb("not referencing previous element unit");
				if (prevElement.message_index !== objPrivateElement.payload.inputs[0].message_index)
					return cb("not referencing previous element message index");
				if (prevElement.output_index !== objPrivateElement.payload.inputs[0].output_index)
					return cb("not referencing previous element output index");
			}
			validatePrivatePayment(conn, objPrivateElement, prevElement, {
				ifError: cb,
				ifOk: function(bStable, input_address){
					objPrivateElement.bStable = bStable;
					objPrivateElement.input_address = input_address;
					if (!bStable)
						bAllStable = false;
					cb();
				}
			});
		},
		function(err){
			if (err)
				return callbacks.ifError(err);
			callbacks.ifOk(bAllStable);
		}
	);
}
```

**File:** validation.js (L214-215)
```javascript
		if (objUnit.messages.length > constants.MAX_MESSAGES_PER_UNIT && !bGenesis)
			return callbacks.ifUnitError("too many messages");
```

**File:** formula/evaluation.js (L2801-2805)
```javascript
	function isTooBigObj(obj) {
		return bPostPemCurvesFix
			? string_utils.isTooBigObj(obj, { lengthLimit: constants.MAX_AA_STRING_LENGTH })
			: string_utils.isTooDeeplyNestedOrHasTooManyNodes(obj);
	}
```

**File:** string_utils.js (L260-284)
```javascript
function isTooDeeplyNestedOrHasTooManyNodes(obj, depthLimit = 100, nodesLimit = 10000) {
	let nodeCount = 0;

	function check(variable, depth){
		if (depth > depthLimit || nodeCount > nodesLimit)
			return true;
		if (variable === null || typeof variable !== "object")
			return false;
		if (Array.isArray(variable)) {
			nodeCount += variable.length;
			for (let v of variable)
				if (check(v, depth + 1))
					return true;
		}
		else {
			nodeCount += Object.keys(variable).length;
			for (let key in variable)
				if (check(variable[key], depth + 1))
					return true;
		}
		return false;
	}

	return check(obj, 1);
}
```
