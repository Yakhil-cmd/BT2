### Title
Unbounded Private-Payment-Chain Processing from a Paired Device Bypasses Size Limits Enforced Elsewhere in Validation - ([File: wallet.js])

### Summary
`wallet.js`'s `handlePrivatePaymentChains()` — the handler for the `private_payments` device-message subject that a paired correspondent device (or hub, forwarding on the correspondent's behalf) can trigger — performs only structural/type checks on the attacker-supplied `body.chains` array before calling `objectHash.getBase64Hash(arrChains)` and iterating every chain with `network.handleOnlinePrivatePayment`. Unlike other externally-reachable inputs in the codebase (unit messages, AA triggers, data feeds), this path has no size/depth cap analogous to `string_utils.isTooBigObj()` or `isTooDeeplyNestedOrHasTooManyNodes()`.

### Finding Description
`handlePrivatePaymentChains(ws, body, from_address, callbacks)` [1](#0-0)  is invoked directly from `handleMessageFromHub()` for the `'private_payments'` subject with no additional gating besides `conf.bIgnorePrivatePayments` [2](#0-1) . The message body originates from a decrypted device-message JSON body that a correspondent device can freely construct — this is functionally identical to a "paired device" or "private-payment counterparty" reachable surface explicitly in scope.

The validation performed is:
```
var arrChains = body.chains;
if (!ValidationUtils.isNonemptyArray(arrChains)) ...
if (!arrChains.every(c => isNonemptyArray(c) && c.every(e => isNonemptyObject(e) && ... )))
``` [3](#0-2) 

This only checks *shape* (non-empty array/object, string/array field presence) — it never bounds:
- the number of chains in `arrChains`,
- the number of elements in each chain `c`,
- the size of `e.payload.inputs` / `e.payload.outputs` arrays, or
- the overall byte size / nesting depth of `body` (no `isTooBigObj()` / `isTooDeeplyNestedOrHasTooManyNodes()` call, which are used elsewhere for comparable attacker-controlled structures, e.g. AA triggers via `string_utils.isTooBigObj(trigger, { lengthLimit: 10e3 })` [4](#0-3) , and device messages received over the wire via `isTooDeeplyNestedOrHasTooManyNodes(objDeviceMessage, 5, 100)` [5](#0-4)  for `hub/deliver`).

Immediately after this shape check, the code computes a full recursive hash over the entire attacker-controlled structure:
```
var cache_key = objectHash.getBase64Hash(arrChains);
``` [6](#0-5) 
and then iterates every chain sequentially with `async.eachSeries`, invoking `network.handleOnlinePrivatePayment` for each one [7](#0-6) , which in turn calls into `private_payment.validateAndSavePrivatePaymentChain` → `indivisibleAsset`/`divisibleAsset` validators, each doing multiple DB queries and hash computations per chain element (see e.g. `indivisible_asset.js` `validatePrivatePayment` which performs several `objectHash.getBase64Hash` calls and DB round-trips per element [8](#0-7) ).

This mirrors the reported bug class exactly: a guard that is supposed to bound resource consumption (content-length / object-size check) is either absent or ineffective for a specific code path, and the full, attacker-sized payload is then processed (hashed, iterated, and pushed through expensive per-element validation) without a cap — enabling memory and CPU exhaustion analogous to the unbounded `response.text()` read in the advisory.

### Impact Explanation
A malicious paired device (a correspondent an ordinary user might pair with for chat/payment purposes, no special privilege required) can send a single `private_payments` device message containing an arbitrarily large `chains` array (many chains, each with many elements, each with large `inputs`/`outputs` arrays) to a victim's wallet/light client. Processing this:
- Forces `objectHash.getBase64Hash()` to hash the entire structure synchronously.
- Forces sequential processing of every chain and every element through `validateAndSavePrivatePaymentChain`, each performing multiple DB queries and additional hash computations.
- For light clients (`conf.bLight`), it additionally triggers `network.requestUnfinishedPastUnitsOfPrivateChains(arrChains)` [9](#0-8) , further amplifying network/DB work per attacker-chosen element.

This can exhaust CPU/memory/DB-connection resources on the victim's node process, rendering it unable to process legitimate payments or confirm new units — a Denial of Service against a wallet/light node triggered by an unprivileged correspondent, consistent with the "network unable to confirm new units" / node disagreement impact bar for this analog set.

### Likelihood Explanation
High likelihood: any paired correspondent device (a normal, low-trust relationship — pairing is common and can be initiated by attacker-controlled contacts, e.g. via a shared pairing link or a textcoin/private-payment file recipient) can send this message directly; the entry point requires only `conf.bIgnorePrivatePayments` to be false (the default). No cryptographic or protocol-level barrier prevents an oversized `body.chains` from reaching `handlePrivatePaymentChains`.

### Recommendation
Add explicit size/count bounds before any hashing or iteration over `body.chains` in `handlePrivatePaymentChains()`, mirroring existing patterns in the codebase:
- Cap `arrChains.length` and each chain's element count against sane constants (e.g. similar to `constants.MAX_MESSAGES_PER_UNIT`/`MAX_INPUTS_PER_PAYMENT_MESSAGE`).
- Call `string_utils.isTooBigObj(body, { lengthLimit: ... })` and/or `isTooDeeplyNestedOrHasTooManyNodes(body, depthLimit, nodesLimit)` on the whole `body` before doing anything else, exactly as done for `hub/deliver` device messages in `network.js` [5](#0-4) .
- Reject the message with `callbacks.ifError(...)` before computing `objectHash.getBase64Hash(arrChains)` if any limit is exceeded.

### Proof of Concept
Conceptual PoC (cannot be executed without live infra, but derivable from the code path):
1. Pair a device with the victim (or use an existing correspondent relationship).
2. Craft a device message with `subject: 'private_payments'` and body:
```json
{
  "chains": [ /* N chains */
    [ { "unit": "<64-char b64>", "payload": { "asset": "<64-char b64>", "inputs": [ {...} /* many */ ], "outputs": [ {...} /* many */ ] } } /* repeated M times per chain */ ]
    /* repeated N times */
  ]
}
```
   choosing N and M large enough (e.g. tens of thousands) to make each field pass the `isNonemptyArray`/`isNonemptyObject`/`isNonemptyString` checks in the `.every()` validator at `wallet.js:959-972`.
3. Encrypt and send via the normal device-message path (`hub/message` / `hub/deliver`), which only checks basic field presence, signature validity, and (for `hub/deliver`) shallow nesting/size on the *outer* device message frame — not on the *decrypted* `private_payments` body, since that check happens only in `network.js` for `hub/deliver`, not inside `wallet.js`'s `handleMessageFromHub`/`handlePrivatePaymentChains`.
4. On receipt, the victim's `handlePrivatePaymentChains` computes `objectHash.getBase64Hash(arrChains)` over the full oversized structure and then sequentially processes every chain/element through DB-backed validation, consuming CPU/memory/DB resources proportional to attacker-chosen N×M with no rejection based on size.

### Citations

**File:** wallet.js (L420-424)
```javascript
			case 'private_payments':
				if (conf.bIgnorePrivatePayments)
					return callbacks.ifError("private payments are ignored");
				handlePrivatePaymentChains(ws, body, from_address, callbacks);
				break;
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

**File:** wallet.js (L973-978)
```javascript
	try {
		var cache_key = objectHash.getBase64Hash(arrChains);
	}
	catch (e) {
		return callbacks.ifError("chains hash failed: " + e.toString());		
	}
```

**File:** wallet.js (L986-987)
```javascript
	if (conf.bLight)
		network.requestUnfinishedPastUnitsOfPrivateChains(arrChains); // it'll work in the background
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

**File:** aa_composer.js (L235-236)
```javascript
	if (string_utils.isTooBigObj(trigger, { lengthLimit: 10e3 }))
		return handle("trigger data is too big");
```

**File:** network.js (L3520-3521)
```javascript
			if (isTooDeeplyNestedOrHasTooManyNodes(objDeviceMessage, 5, 100))
				return sendErrorResponse(ws, tag, "device message is too deeply nested or has too many nodes");
```

**File:** indivisible_asset.js (L20-139)
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
		
	var payload = objPrivateElement.payload;
	if (!ValidationUtils.isStringOfLength(payload.asset, constants.HASH_LENGTH))
		return callbacks.ifError("invalid asset in private payment");
	if (!ValidationUtils.isPositiveInteger(payload.denomination))
		return callbacks.ifError("invalid denomination in private payment");
	if (!ValidationUtils.isNonemptyObject(objPrivateElement.output))
		return callbacks.ifError("no output");
	if (!ValidationUtils.isNonnegativeInteger(objPrivateElement.output_index))
		return callbacks.ifError("invalid output index");
	if (!ValidationUtils.isNonemptyArray(payload.outputs))
		return callbacks.ifError("invalid outputs");
	var our_hidden_output = payload.outputs[objPrivateElement.output_index];
	if (!ValidationUtils.isNonemptyObject(payload.outputs[objPrivateElement.output_index]))
		return callbacks.ifError("no output at output_index");
	if (!ValidationUtils.isValidAddress(objPrivateElement.output.address))
		return callbacks.ifError("bad address in output");
	if (!ValidationUtils.isNonemptyString(objPrivateElement.output.blinding))
		return callbacks.ifError("bad blinding in output");
	try {
		var expected_output_hash = objectHash.getBase64Hash(objPrivateElement.output);
	}
	catch (e) {
		return callbacks.ifError("failed to calc output hash: " + e.message);
	}
	if (expected_output_hash !== our_hidden_output.output_hash)
		return callbacks.ifError("output hash doesn't match, output="+JSON.stringify(objPrivateElement.output)+", hash="+our_hidden_output.output_hash);
	if (!ValidationUtils.isArrayOfLength(payload.inputs, 1))
		return callbacks.ifError("inputs array must be 1 element long");
	var input = payload.inputs[0];
	if (!ValidationUtils.isNonemptyObject(input))
		return callbacks.ifError("no inputs[0]");
	
	profiler.start();
	validation.initPrivatePaymentValidationState(
		conn, objPrivateElement.unit, objPrivateElement.message_index, payload, callbacks.ifError, 
		function(bStable, objPartialUnit, objValidationState){
		
			profiler.stop('initPrivatePaymentValidationState');
			var arrFuncs = [];
			var spend_proof;
			var input_address; // from which address the money is sent
			if (!input.type){ // transfer
				if (typeof input.unit !== 'string')
					return callbacks.ifError("invalid unit in private payment");
				if (!ValidationUtils.isNonnegativeInteger(input.message_index))
					return callbacks.ifError("invalid input message_index");
				if (!ValidationUtils.isNonnegativeInteger(input.output_index))
					return callbacks.ifError("invalid input output_index");
				if (!objPrevPrivateElement || !objPrevPrivateElement.output || !objPrevPrivateElement.output.blinding)
					return callbacks.ifError("no prev output blinding");
				if (!objPrevPrivateElement.payload || !objPrevPrivateElement.payload.outputs)
					return callbacks.ifError("no prev outputs");
				var src_output = objPrevPrivateElement.output;
				var prev_hidden_output = objPrevPrivateElement.payload.outputs[input.output_index];
				if (!prev_hidden_output)
					return callbacks.ifError("no prev hidden output");
				input_address = src_output.address;
				try {
					spend_proof = objectHash.getBase64Hash({
						asset: payload.asset,
						unit: input.unit,
						message_index: input.message_index,
						output_index: input.output_index,
						address: src_output.address,
						amount: prev_hidden_output.amount,
						blinding: src_output.blinding
					});
				}
				catch (e) {
					return callbacks.ifError("failed to calc transfer spend proof: " + e.message);
				}
				console.log("validation spend proof: "+JSON.stringify({
					asset: payload.asset,
					unit: input.unit,
					message_index: input.message_index,
					output_index: input.output_index,
					address: src_output.address,
					amount: prev_hidden_output.amount,
					blinding: src_output.blinding
				}));
				arrFuncs.push(validateSourceOutput);
				objValidationState.src_coin = {
					src_output: src_output,
					denomination: payload.denomination,
					amount: prev_hidden_output.amount
				};
```
