### Title
Unbounded memory/CPU consumption from hashing and structurally-shallow-validating attacker-controlled private-payment chains before size limits are enforced - (File: wallet.js)

### Summary
`handlePrivatePaymentChains()` in `wallet.js` receives the `private_payments` device message body (`body.chains`) from a paired/correspondent device and, before any bounded size validation is applied, computes `objectHash.getBase64Hash(arrChains)` over the entire attacker-supplied structure and iterates over it with only a shallow structural check. The numeric/size anti-spam limits that exist elsewhere in the codebase (`MAX_INPUTS_PER_PAYMENT_MESSAGE`, `MAX_OUTPUTS_PER_PAYMENT_MESSAGE`, `isTooBigObj`, `isTooDeeplyNestedOrHasTooManyNodes`) are only applied later, one element at a time, deep inside `validation.validatePaymentInputsAndOutputs()`. This mirrors the reported JSON-RPC pattern: the server fully materializes/hashes the whole untrusted payload before enforcing any size cap, creating a window where an oversized or highly nested `chains` array can be fully processed in memory.

### Finding Description
`handlePrivatePaymentChains(ws, body, from_address, callbacks)` [1](#0-0)  only validates presence/type of fields on every chain element (`isNonemptyObject`, `isNonemptyString`, `isNonemptyArray`) — it does not bound:
- the number of chains in `arrChains`,
- the number of elements per chain,
- the number of `payload.inputs` / `payload.outputs` per element,
- or the length of any string field (`asset`, `unit`, `blinding`, etc.).

Immediately after this shallow check, the code computes a hash over the **entire** raw structure:
```
var cache_key = objectHash.getBase64Hash(arrChains);
``` [2](#0-1) 

This is directly analogous to the reported bug: `getBase64Hash` walks and serializes the whole object graph (comparable to `serde_json::to_raw_value` on the full `ResponseWrapper`) before any per-element size cap has been enforced. The real anti-spam limits (`MAX_INPUTS_PER_PAYMENT_MESSAGE`, `MAX_OUTPUTS_PER_PAYMENT_MESSAGE`, `MAX_CAP`, address/blinding length checks) live in `validatePaymentInputsAndOutputs()` [3](#0-2)  and are reached only later, one chain element at a time via `async.eachSeries` over `arrChains` [4](#0-3) , and only after the head element of each chain is fully accepted and (in many code paths) persisted to the `unhandled_private_payments` table via `JSON.stringify(arrPrivateElements)` [5](#0-4) .

Similarly, `object_length.getLength()` [6](#0-5)  and the general `isTooBigObj`/`isTooDeeplyNestedOrHasTooManyNodes` guards [7](#0-6)  that gate unit content and AA formula intermediates are **not** applied to the raw `chains` body before it is hashed and iterated in `wallet.js`.

Because this handler is invoked from `handleMessageFromHub`, reachable by any correspondent/paired device that can deliver a `private_payments` (or forwarded `private_payment`) message through the hub relay, an attacker who is a legitimate private-payment counterparty (or a paired device that got added as correspondent, e.g. via a one-time pairing link) can construct a `chains` array with an extremely large number of chains/elements or very large string fields and send it. The receiver will decrypt, `JSON.parse`, run the shallow `.every()` check (which passes for arbitrarily large arrays/strings), and then hash the whole thing and iterate every chain — all before the real, bounded per-item validators run.

### Impact Explanation
An attacker who is a correspondent device (paired wallet, chat partner, or private-payment counterparty) can cause the victim's wallet process to spend excessive CPU/memory hashing and iterating an oversized, attacker-crafted `chains` payload before any of the codebase's existing anti-spam limits are applied. This can degrade or crash the victim wallet process (denial of service against a specific node/wallet), matching the report's "OOM / severe resource exhaustion before enforcement" bug class. It does not directly cause double-spend or fund loss, but it can deny a node's ability to process further messages/transactions (including confirming new transactions) while it's busy or crashed, which fits the "network unable to confirm new units" outcome for the affected node.

### Likelihood Explanation
Medium. The attacker must already be a known correspondent device (an established private-payment counterparty or paired device), which requires some prior interaction (pairing), but no privileged/operator access is needed — this is the "private-payment counterparty or paired device" actor explicitly allowed by scope. Constructing an oversized `chains` array is trivial for the attacker since the wallet's message layer does not appear to impose a payload-size cap earlier in the pipeline (`decryptPackage`/`handleJustsaying` in `device.js` perform structural/signature checks only, not size checks) [8](#0-7) .

### Recommendation
- Apply bounded validation (max number of chains, max elements per chain, max inputs/outputs per element, max string field lengths, and an overall `isTooBigObj`/depth-and-node-count check) to `body.chains` in `handlePrivatePaymentChains()` immediately after the initial type check and **before** calling `objectHash.getBase64Hash(arrChains)` or iterating with `async.eachSeries`.
- Enforce the same limits before persisting unvalidated chains into `unhandled_private_payments` in `handleOnlinePrivatePayment()`.
- Consider capping the raw decrypted device-message size in `device.js` before `JSON.parse`, mirroring the size-budget approach recommended for the JSON-RPC report.

### Proof of Concept
1. Attacker device pairs with / is an existing correspondent of the victim wallet (e.g., via a one-time pairing code, a common private-payment counterparty flow).
2. Attacker crafts a `private_payments` device message whose `body.chains` is an array containing a very large number of well-formed-but-oversized chain elements (e.g., thousands of chains, each with large `payload.inputs`/`payload.outputs` arrays or very long strings in `blinding`/`asset`/`unit` fields), satisfying only the shallow `isNonemptyObject`/`isNonemptyString`/`isNonemptyArray` checks in the `.every()` guard.
3. Attacker encrypts and sends this message to the victim device through the hub (`hub/message`) or directly (`private_payment`/`private_payments` justsaying/request).
4. Victim's `device.js` decrypts and `JSON.parse`s the full message with no size cap, then dispatches to `wallet.js`'s `handlePrivatePaymentChains`, which passes the shallow check and calls `objectHash.getBase64Hash(arrChains)` on the full oversized structure, then iterates every chain — consuming CPU/memory proportional to the attacker-chosen size, before the bounded per-item validators (`MAX_INPUTS_PER_PAYMENT_MESSAGE`, etc.) in `validation.js` are ever reached.

### Citations

**File:** wallet.js (L955-978)
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

**File:** validation.js (L2128-2151)
```javascript
function validatePaymentInputsAndOutputs(conn, payload, objAsset, message_index, objUnit, objValidationState, callback){
	
//	if (objAsset)
//		profiler2.start();
	var denomination = payload.denomination || 1;
	var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
	var arrInputAddresses = []; // used for non-transferrable assets only
	var arrOutputAddresses = [];
	var total_input = 0;
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
	if (payload.outputs.length > constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE && !storage.isGenesisUnit(objUnit.unit))
		return callback("too many outputs");
	
	if (objAsset && objAsset.fixed_denominations && payload.inputs.length !== 1)
		return callback("fixed denominations payment must have 1 input");

	const isValidAddressWithCase = objValidationState.last_ball_mci >= constants.timestampUpgradeMci ? ValidationUtils.isValidAddress : ValidationUtils.isValidAddressAnyCase;

	var total_output = 0;
	var prev_address = ""; // if public, outputs must be sorted by address
	var prev_amount = 0;
	var count_open_outputs = 0;
	for (var i=0; i<payload.outputs.length; i++){
```

**File:** network.js (L2390-2402)
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
```

**File:** object_length.js (L9-50)
```javascript
function getLength(value, bWithKeys) {
	let cache = new WeakMap();  // object to length
	function _getLength(value) {
		if (value === null)
			return 0;
		switch (typeof value) {
			case "string":
				return value.length;
			case "number":
				if (!isFinite(value))
					throw Error("invalid number: " + value);
				return 8;
				//return value.toString().length;
			case "object":
				// return cached result if already processed
				if (cache.has(value))
					return cache.get(value);
				var len = 0;
				if (Array.isArray(value))
					value.forEach(function (element) {
						len += _getLength(element);
					});
				else
					for (var key in value) {
						if (!Object.prototype.hasOwnProperty.call(value, key))
							throw Error("object has non-own property " + key + " in " + JSON.stringify(value));
						if (typeof value[key] === "undefined")
							throw Error("undefined at " + key + " of " + JSON.stringify(value));
						if (bWithKeys)
							len += key.length;
						len += _getLength(value[key]);
					}
				cache.set(value, len);  // memoize for future references
				return len;
			case "boolean":
				return 1;
			default:
				throw Error("unknown type=" + (typeof value) + " of " + value);
		}
	}
	return _getLength(value);
}
```

**File:** string_utils.js (L260-323)
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

function isTooBigObj(obj, { depthLimit = 100, nodesLimit = 10000, lengthLimit = 1000000 }) {
	let nodeCount = 0;
	let length = 0;

	function check(variable, depth){
		if (depth > depthLimit || nodeCount > nodesLimit || length > lengthLimit)
			return true;
		if (typeof variable === "string")
			length += variable.length;
		else if (typeof variable === "number" || typeof variable === "boolean")
			length += variable.toString().length;
		else if (variable === null)
			length += 4; // "null"
		else if (typeof variable !== "object")
			throw Error("isTooBigObj: unexpected type=" + (typeof variable) + " of " + variable);
		if (length > lengthLimit)
			return true;
		if (typeof variable !== "object" || variable === null)
			return false;
		if (Array.isArray(variable)) {
			nodeCount += variable.length;
			for (let v of variable)
				if (check(v, depth + 1))
					return true;
		}
		else {
			const keys = Object.keys(variable);
			nodeCount += keys.length;
			length += keys.reduce((sum, key) => sum + key.length, 0);
			for (let key in variable)
				if (check(variable[key], depth + 1))
					return true;
		}
		return false;
	}

	return check(obj, 1);
}
```

**File:** device.js (L146-221)
```javascript
		// I'm connected to a hub, received a message through the hub
		case 'hub/message':
			var objDeviceMessage = body.message;
			var message_hash = body.message_hash;
			var respondWithError = function(error){
				network.sendError(ws, error);
				network.sendJustsaying(ws, 'hub/delete', message_hash);
			};
			if (!ValidationUtils.isNonemptyString(message_hash) || !objDeviceMessage || !objDeviceMessage.signature || !objDeviceMessage.pubkey || !objDeviceMessage.to
					|| !objDeviceMessage.encrypted_package || !objDeviceMessage.encrypted_package.dh
					|| !objDeviceMessage.encrypted_package.dh.sender_ephemeral_pubkey 
					|| !objDeviceMessage.encrypted_package.dh.recipient_ephemeral_pubkey 
					|| !objDeviceMessage.encrypted_package.encrypted_message
					|| !objDeviceMessage.encrypted_package.iv || !objDeviceMessage.encrypted_package.authtag)
				return network.sendError(ws, "missing fields");
			if (objDeviceMessage.to !== getMyDeviceAddress())
				return network.sendError(ws, "not mine");
			try {
				const bOldHashIsCorrect = (message_hash === objectHash.getBase64Hash(objDeviceMessage));
				if (!bOldHashIsCorrect && message_hash !== objectHash.getBase64Hash(objDeviceMessage, true))
					return network.sendError(ws, "wrong hash");
				if (!ecdsaSig.verify(objectHash.getDeviceMessageHashToSign(objDeviceMessage), objDeviceMessage.signature, objDeviceMessage.pubkey))
					return respondWithError("wrong message signature");
			}
			catch(e){
				return respondWithError("failed to caculate message hash to sign:" + e);
			}
			// end of checks on the open (unencrypted) part of the message. These checks should've been made by the hub before accepting the message
			
			// decrypt the message
			try {
				var json = decryptPackage(objDeviceMessage.encrypted_package);
			}
			catch(e){
				return respondWithError("failed to decrypt: " + e);
			}
			if (!json)
				return respondWithError("failed to decrypt");
			
			// who is the sender
			var from_address = objectHash.getDeviceAddress(objDeviceMessage.pubkey);
			// the hub couldn't mess with json.from as it was encrypted, but it could replace the objDeviceMessage.pubkey and re-sign. It'll be caught here
			if (from_address !== json.from) 
				return respondWithError("wrong message signature");
			
			var handleMessage = function(bIndirectCorrespondent){
				eventBus.emit("handle_message_from_hub", ws, json, objDeviceMessage.pubkey, bIndirectCorrespondent, {
					ifError: function(err){
						respondWithError(err);
					},
					ifOk: function(){
						network.sendJustsaying(ws, 'hub/delete', message_hash);
					}
				});
			};
			
			
			// check that we know this device
			db.query("SELECT hub, is_indirect FROM correspondent_devices WHERE device_address=?", [from_address], function(rows){
				if (rows.length > 0){
					if (json.device_hub && typeof json.device_hub === 'string' && json.device_hub.length <= 200 && network.isValidWsUrl(conf.WS_PROTOCOL + json.device_hub) && json.device_hub !== rows[0].hub) // update correspondent's home address if necessary
						db.query("UPDATE correspondent_devices SET hub=? WHERE device_address=?", [json.device_hub, from_address], function(){
							handleMessage(rows[0].is_indirect);
						});
					else
						handleMessage(rows[0].is_indirect);
				}
				else{ // correspondent not known
					var arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"];
					if (arrSubjectsAllowedFromNoncorrespondents.indexOf(json.subject) === -1){
						respondWithError("correspondent not known and not whitelisted subject");
						return;
					}
					handleMessage(false);
				}
			});
```
