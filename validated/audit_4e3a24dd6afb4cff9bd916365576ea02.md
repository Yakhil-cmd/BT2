### Title
Node/wallet crash via `throw Error` on malformed `amount` in private indivisible-asset transfer chains - ([File: validation.js])

### Summary
When validating a private (indivisible, fixed-denomination) asset transfer, `validatePaymentInputsAndOutputs()` reads pre-populated `objValidationState.src_coin` fields (`denomination`, `amount`, `src_output`) and, instead of returning a normal validation error when they are malformed, uses `throw Error(...)`. These `src_coin` values are populated directly from attacker-controlled private-payment-chain data in `indivisible_asset.js` `validatePrivatePayment()` without type/positivity checks. A malicious private-payment counterparty can craft a chain element whose hidden output has a non-integer/negative `amount`, causing the recipient's node to throw an uncaught exception while validating the chain, crashing the process — the same "malformed record triggers assertion/exception, daemon exits" bug class as CVE‑2016‑8864.

### Finding Description
For private fixed-denomination assets, source-output data cannot be looked up from the DB (the whole chain is validated before anything is saved), so it is pre-populated into `objValidationState.src_coin`: [1](#0-0) 

Note that `src_coin.amount` is set to `prev_hidden_output.amount`, taken straight from `objPrevPrivateElement.payload.outputs[input.output_index]` — an object supplied by the sending peer in the private payment chain. The only check performed on it in `validatePrivatePayment()` is that the object exists (`if (!prev_hidden_output) return callbacks.ifError(...)`), not that `amount` is a valid positive integer: [2](#0-1) 

Because the output object (including `amount`) is only ever consumed via its own self-computed hash (`output_hash`), the sender fully controls its contents — they can set `amount` to a string, float, negative number, or other non-integer value and still produce a matching hash.

Later, when the recipient (or a hub/witness re-validating the chain) processes the "transfer" input for this asset, `validatePaymentInputsAndOutputs()` reads these fields and asserts on them with `throw Error` rather than `return cb(...)`: [3](#0-2) 

Since `isPositiveInteger` rejects non-integers, negative numbers, or non-numeric types, an attacker-controlled `amount` that fails this check triggers `throw Error("no src coin amount")` (or `"no denomination in src coin"` / `"no src_output"`) synchronously inside the `async.eachOfSeries` iterator used to walk the payment inputs, rather than surfacing as a normal validation callback error. This is inconsistent with every other check in the same function, which return `cb("...")` to gracefully fail validation.

### Impact Explanation
An uncaught synchronous exception thrown deep inside asynchronous validation code is not routed through the normal `ifUnitError`/`ifError` callback path used elsewhere in `validation.js` and `indivisible_asset.js` (e.g. compare with the graceful error handling pattern in `validate()`'s callback usages: [4](#0-3) ). Depending on the calling context (`indivisible_asset.js` `validateAndSavePrivatePaymentChain`/`getSavingCallbacks`, [5](#0-4) ), this exception can escape any try/catch and crash the Node.js process handling the private payment (wallet, hub relaying a private payment notification, or any node validating the chain), producing a denial of service consistent with the "assertion failure and daemon exit" pattern described in CVE-2016-8864, but reachable purely from data supplied by a private-payment counterparty rather than a privileged party.

### Likelihood Explanation
Any private-payment counterparty (the party crafting/sending the private-element chain to a payee, hub, or cosigner for a private fixed-denomination asset) can trivially construct such a payload — no signature bypass or special privilege is required, only that the self-computed `output_hash` matches the (attacker-controlled) output object. This satisfies the requirement of the class of "private payment chain" analog reachable by an unprivileged sender.

### Recommendation
Replace the `throw Error(...)` calls in the `src_coin` validation block of `validatePaymentInputsAndOutputs()` (`validation.js` around lines 2415–2424) with `return cb("...")` so malformed private-payment `src_coin` data results in a normal validation error rather than an unhandled exception. Additionally, validate `prev_hidden_output.amount` (and other fields) as a positive integer in `indivisible_asset.js`'s `validatePrivatePayment()` before it is placed into `objValidationState.src_coin`, mirroring the checks already applied to `payload.denomination` and other fields in that function ( [6](#0-5) ).

### Proof of Concept
1. Attacker (a private-payment counterparty) constructs a private payment chain for a private, fixed-denomination indivisible asset.
2. In the chain element preceding a "transfer" input, the attacker sets the hidden output's `amount` field to a non-integer value (e.g., `"1e400"`, `1.5`, or `-5`), and computes `output_hash` over that exact object so it passes the hash-match check at: [7](#0-6) 
3. The attacker sends this chain to a recipient/hub for validation (e.g., via `parsePrivatePaymentChain` → `validatePrivatePayment` → `validation.validatePayment` → `validatePaymentInputsAndOutputs`).
4. When the "transfer" input for this private fixed-denomination asset is processed, `objValidationState.src_coin.amount` fails `isPositiveInteger`, and the code executes `throw Error("no src coin amount")` at `validation.js:2423-2424`, crashing the validating process instead of returning a normal validation failure.

### Citations

**File:** indivisible_asset.js (L55-82)
```javascript
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
```

**File:** indivisible_asset.js (L106-139)
```javascript
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

**File:** indivisible_asset.js (L838-862)
```javascript
			validation.validate(objJoint, {
				ifUnitError: function(err){
					combined_unlock();
					callbacks.ifError("Validation error: "+err);
				//	throw Error("unexpected validation error: "+err);
				},
				ifJointError: function(err){
					throw Error("unexpected validation joint error: "+err);
				},
				ifTransientError: function(err){
					throw Error("unexpected validation transient error: "+err);
				},
				ifNeedHashTree: function(){
					throw Error("unexpected need hash tree");
				},
				ifNeedParentUnits: function(arrMissingUnits){
					throw Error("unexpected dependencies: "+arrMissingUnits.join(", "));
				},
				ifOk: function(objValidationState, validation_unlock){
					console.log("Private OK "+objValidationState.sequence);
					if (objValidationState.sequence !== 'good'){
						validation_unlock();
						combined_unlock();
						return callbacks.ifError("Indivisible asset bad sequence "+objValidationState.sequence);
					}
```

**File:** validation.js (L445-472)
```javascript
			function(err){
				if(err){
					if (profiler.isStarted())
						profiler.stop('validation-advanced-stability');
					// We might have advanced the stability point and have to commit the changes as the caches are already updated.
					// There are no other updates/inserts/deletes during validation
					commit_fn(function(){
						var consumed_time = Date.now()-start_time;
						profiler.add_result('failed validation', consumed_time);
						console.log(objUnit.unit+" validation "+JSON.stringify(err)+" took "+consumed_time+"ms");
						if (!external_conn)
							conn.release();
						unlock();
						if (typeof err === "object"){
							if (err.error_code === "unresolved_dependency")
								callbacks.ifNeedParentUnits(err.arrMissingUnits, err.bRequestPrunedContent);
							else if (err.error_code === "need_hash_tree") // need to download hash tree to catch up
								callbacks.ifNeedHashTree();
							else if (err.error_code === "invalid_joint") // ball found in hash tree but with another unit
								callbacks.ifJointError(err.message);
							else if (err.error_code === "transient")
								callbacks.ifTransientError(err.message);
							else
								throw Error("unknown error code");
						}
						else
							callbacks.ifUnitError(err);
					});
```

**File:** validation.js (L2415-2424)
```javascript
					if (objAsset && objAsset.is_private && objAsset.fixed_denominations){
						if (!objValidationState.src_coin)
							throw Error("no src_coin");
						var src_coin = objValidationState.src_coin;
						if (!src_coin.src_output)
							throw Error("no src_output");
						if (!isPositiveInteger(src_coin.denomination))
							throw Error("no denomination in src coin");
						if (!isPositiveInteger(src_coin.amount))
							throw Error("no src coin amount");
```
