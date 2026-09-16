### Title
Unbounded private-payment chain size allows resource-exhaustion DoS via device message - (File: wallet.js)

### Summary
`handlePrivatePaymentChains()` in `wallet.js` accepts a `chains` array sent by a paired correspondent device (an untrusted, unprivileged private-payment counterparty) with no limit on the number of chains, the number of elements per chain, or the size of each element's `payload`/`inputs`/`outputs`. This mirrors the Discourse bug class (BIT-discourse-2023-22739 / GHSA-rqgr-g6v7-jcfc): "no limit on data contained in a draft ... forcing the instance to a crawl."

### Finding Description
`wallet.handlePrivatePaymentChains(ws, body, from_address, callbacks)` [1](#0-0)  only validates:
- `arrChains` is a non-empty array
- each chain `c` is a non-empty array
- each element `e` has minimally well-formed fields (`unit`, `payload.asset`, non-empty `inputs`/`outputs` arrays of non-empty objects)

There is **no cap** on:
- `arrChains.length` (number of chains sent in one device message)
- the length of each individual chain (`c.length`, i.e. number of private elements/hops)
- the size of `payload.outputs`/`payload.inputs` arrays or the size of arbitrary string fields inside them (e.g., `blinding`, `output_hash`, or extraneous fields not explicitly checked by `hasFieldsExcept`)

After the lightweight structural check, the code computes a hash over the *entire* `arrChains` blob with `objectHash.getBase64Hash(arrChains)` [2](#0-1) , and then iterates each chain with `async.eachSeries`, calling `network.handleOnlinePrivatePayment(ws, arrPrivateElements, true, ...)` for every one [3](#0-2) .

For light clients (the common wallet configuration), `handleOnlinePrivatePayment` immediately persists the raw chain to the database as a JSON blob with no size check before validation: `JSON.stringify(arrPrivateElements)` is inserted into `unhandled_private_payments` [4](#0-3) , and for multi-element chains it triggers `updateLinkProofsOfPrivateChain`, which performs a network round-trip (`light/get_link_proofs`) per chain [5](#0-4) .

By contrast, every other unprivileged-writable structure in ocore that we examined enforces explicit size limits: unit length (`MAX_UNIT_LENGTH`), messages per unit (`MAX_MESSAGES_PER_UNIT`), inputs/outputs per payment (`MAX_INPUTS_PER_PAYMENT_MESSAGE`/`MAX_OUTPUTS_PER_PAYMENT_MESSAGE`) [6](#0-5) , data feed name/value length and count (`MAX_DATA_FEED_NAME_LENGTH`, `MAX_DATA_FEED_VALUE_LENGTH`, `MAX_DATA_FEEDS_PER_MESSAGE`) [7](#0-6) , AA state-var size (`MAX_STATE_VAR_VALUE_LENGTH`) [8](#0-7) , AA string/array/dictionary sizes (`MAX_AA_STRING_LENGTH`, `isTooBigObj`) [9](#0-8) , and device-message overall length via `isTooDeeplyNestedOrHasTooManyNodes`/`max_message_length` for `hub/deliver` [10](#0-9) . The `private_payments` subject handled in `wallet.js`, however, is delivered as an already-decrypted device-message body and is processed by `handlePrivatePaymentChains` without any equivalent bound on the `chains` array's cardinality or nesting depth before expensive hashing/DB/network work is performed per element.

### Impact Explanation
A paired correspondent (private-payment counterparty, which is by design an untrusted/unprivileged party relative to the recipient's wallet) can send a single `private_payments` device message containing an extremely large `chains` array (many chains, each with many chain elements, each with maximally-sized string fields). This forces the recipient node/wallet to:
- Repeatedly hash large JSON structures (`objectHash.getBase64Hash`)
- Insert large JSON blobs into the database queue table `unhandled_private_payments`
- Issue link-proof requests to the light vendor per chain

This can degrade or stall wallet/hub processing of legitimate private payments and chat messages, consistent with the referenced CVE's "forcing the instance to a crawl" impact — a resource-exhaustion DoS reachable by a private-payment counterparty without any privileged access.

### Likelihood Explanation
Likelihood is Medium: the attacker needs only to be an established chat/pairing correspondent capable of exchanging private payments (a normal, low-privilege relationship in ocore's wallet/chat model), and the payload can be constructed and sent trivially without requiring the victim to accept a real payment. No unit posting, mining, or on-chain fees are required since the message is delivered off-chain via the wallet/hub messaging channel.

### Recommendation
Add explicit bounds in `handlePrivatePaymentChains` (and in `network.handleOnlinePrivatePayment`) before any hashing/DB/network work is performed:
- Cap `arrChains.length` to a reasonable maximum number of concurrent chains per message.
- Cap the length of each individual chain (`c.length`).
- Cap the size of `payload.inputs`/`payload.outputs` per element and the length of string fields (`blinding`, `output_hash`, `asset`, etc.), consistent with existing constants such as `MAX_INPUTS_PER_PAYMENT_MESSAGE`/`MAX_OUTPUTS_PER_PAYMENT_MESSAGE`.
- Apply an overall serialized-size/nesting check (e.g., reuse `isTooDeeplyNestedOrHasTooManyNodes`/a byte-length cap) on `body` before any processing, similar to the checks already applied to `hub/deliver` device messages.

### Proof of Concept
1. Establish a paired-device/correspondent relationship with the victim wallet (normal onboarding, e.g. via pairing code — no special privilege needed).
2. Send a `private_payments` device message whose `body.chains` is an array containing a very large number of chains (or a small number of very long chains), each chain element populated with maximally-sized but structurally-valid `payload.inputs`/`payload.outputs` and long strings in unchecked fields.
3. Observe the victim's `handlePrivatePaymentChains` hash the entire blob, iterate every chain via `network.handleOnlinePrivatePayment`, and (for light wallets) write each large chain's JSON into `unhandled_private_payments` and trigger a network round-trip per chain — consuming CPU, DB, and network resources disproportionate to a single device message, without any structural size limit rejecting the request beforehand.

*(Note: I was unable to fully trace every downstream consumer of `unhandled_private_payments` or confirm the exact practical resource cost per chain element in this review pass; a background Devin session with runtime access could benchmark actual impact and quantify the exploitable size ratio precisely.)*

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

**File:** wallet.js (L1020-1063)
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
```

**File:** network.js (L2390-2401)
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
```

**File:** network.js (L2404-2409)
```javascript
	if (conf.bLight && arrPrivateElements.length > 1){
		savePrivatePayment(function(){
			updateLinkProofsOfPrivateChain(arrPrivateElements, unit, message_index, output_index);
			rerequestLostJointsOfPrivatePayments(); // will request the head element
		});
		return;
```

**File:** network.js (L3508-3521)
```javascript
		// I'm a hub, the peer wants to deliver a message to one of my clients
		case 'hub/deliver':
			var objDeviceMessage = params;
			if (!objDeviceMessage || !objDeviceMessage.signature || !objDeviceMessage.pubkey || !objDeviceMessage.to
					|| !objDeviceMessage.encrypted_package || !objDeviceMessage.encrypted_package.dh
					|| !objDeviceMessage.encrypted_package.dh.sender_ephemeral_pubkey 
					|| !objDeviceMessage.encrypted_package.dh.recipient_ephemeral_pubkey 
					|| !objDeviceMessage.encrypted_package.encrypted_message
					|| !objDeviceMessage.encrypted_package.iv || !objDeviceMessage.encrypted_package.authtag)
				return sendErrorResponse(ws, tag, "missing fields");
			if (!ValidationUtils.isValidDeviceAddress(objDeviceMessage.to))
				return sendErrorResponse(ws, tag, "invalid to address");
			if (isTooDeeplyNestedOrHasTooManyNodes(objDeviceMessage, 5, 100))
				return sendErrorResponse(ws, tag, "device message is too deeply nested or has too many nodes");
```

**File:** constants.js (L42-59)
```javascript
// anti-spam limits
exports.MAX_AUTHORS_PER_UNIT = 16;
exports.MAX_PARENTS_PER_UNIT = 16;
exports.MAX_MESSAGES_PER_UNIT = 128;
exports.MAX_SPEND_PROOFS_PER_MESSAGE = 128;
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_OUTPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_CHOICES_PER_POLL = 128;
exports.MAX_CHOICE_LENGTH = 64;
exports.MAX_DENOMINATIONS_PER_ASSET_DEFINITION = 64;
exports.MAX_ATTESTORS_PER_ASSET = 64;
exports.MAX_DATA_FEED_NAME_LENGTH = 64;
exports.MAX_DATA_FEED_VALUE_LENGTH = 64;
exports.MAX_DATA_FEEDS_PER_MESSAGE = 1024;
exports.MAX_AUTHENTIFIER_LENGTH = 4096;
exports.MAX_CAP = 9e15;
exports.MAX_COMPLEXITY = process.env.MAX_COMPLEXITY || 100;
exports.MAX_UNIT_LENGTH = process.env.MAX_UNIT_LENGTH || 5e6;
```

**File:** validation.js (L1925-1951)
```javascript
		case "data_feed":
			if (objValidationState.bHasDataFeed)
				return callback("can be only one data feed");
			objValidationState.bHasDataFeed = true;
			if (!isNonemptyObject(payload))
				return callback("data feed payload must be non-empty object");
			if (Object.keys(payload).length * objUnit.authors.length > constants.MAX_DATA_FEEDS_PER_MESSAGE)
				return callback("too many data feeds in message");
			for (var feed_name in payload){
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return callback("feed name "+feed_name+" too long");
				if (feed_name.indexOf('\n') >=0 )
					return callback("feed name "+feed_name+" contains \\n");
				var value = payload[feed_name];
				if (typeof value === 'string'){
					if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
						return callback("data feed value too long: " + value);
					if (value.indexOf('\n') >=0 )
						return callback("value "+value+" of feed name "+feed_name+" contains \\n");
				}
				else if (typeof value === 'number'){
					if (!isInteger(value))
						return callback("fractional numbers not allowed in data feeds");
				}
				else
					return callback("data feed "+feed_name+" must be string or number");
			}
```

**File:** aa_composer.js (L1552-1553)
```javascript
				if (newSize > constants.MAX_STATE_VAR_VALUE_LENGTH)
					return cb(`state var value too long: ${newSize}`);
```

**File:** formula/evaluation.js (L1130-1167)
```javascript
			case 'array':
				var arrItemExprs = arr[1];
				if (arrItemExprs.length > 100 && bPostPemCurvesFix)
					return setFatalError("array literal is too long", { arr }, false, cb);
				var prevCount = count;
				var arrItems = [];
				async.eachSeries(
					arrItemExprs,
					function (item_expr, cb2) {
						evaluate(item_expr, function (res) {
							if (fatal_error)
								return cb2(fatal_error);
							if (res instanceof wrappedObject)
								arrItems.push(string_utils.cloneDeep(res.obj)); // might be frozen
							else {
								if (!isValidValue(res))
									return setFatalError("bad value " + res, { arr }, undefined, cb2);
								if (Decimal.isDecimal(res))
									res = res.toNumber();
								arrItems.push(res);
							}
							if (count - prevCount >= 100) {
								prevCount = count;
								if (isTooBigObj(arrItems))
									return setFatalError("intermediate array is too big", { arr }, undefined, cb2);
							}
							cb2();
						})
					},
					function (err) {
						if (fatal_error)
							return cb(false);
						if (isTooBigObj(arrItems))
							return setFatalError("resulting array is too big", { arr }, false, cb);
						cb(new wrappedObject(arrItems));
					}
				);
				break;
```
