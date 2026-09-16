### Title
Unhandled `throw Error` on missing `amount` field in a private-payment chain crashes the node - (File: `validation.js`)

### Summary
Analogous to CVE-2023-37012 (Open5GS MME crashing on a malformed ASN.1 field via `assert`), `ocore` contains an assertion-style `throw Error(...)` in the payment-input validation path that fires when a required numeric field in a private, indivisible-asset payment chain is missing or malformed. Because this throw happens deep inside asynchronous DB-query callbacks with no surrounding `try/catch`, it is an uncaught exception that crashes the Node.js process — a remote, single-message DoS triggered by an untrusted private-payment counterparty, not a malicious peer/hub.

### Finding Description
When validating a "transfer" input of a private, fixed-denomination (indivisible) asset, `validatePaymentInputsAndOutputs` cannot look up the spent output in the database (because the whole private chain is validated before anything is persisted). Instead it trusts a pre-populated `objValidationState.src_coin` object and asserts its shape with hard `throw Error(...)` calls instead of returning a validation error via callback: [1](#0-0) 

`src_coin` is populated in `indivisible_asset.js`’s `validatePrivatePayment` from the *previous* chain element's hidden output, specifically `prev_hidden_output.amount`: [2](#0-1) 

Crucially, `validatePrivatePayment` only checks that `prev_hidden_output` exists as a non-empty concept via `objPrevPrivateElement.output`/`payload.outputs`, but it never verifies `prev_hidden_output.amount` is a positive integer before copying it into `src_coin.amount`: [3](#0-2) 

The chain (`arrPrivateElements`, ordered newest-first) is validated with `async.forEachOfSeries`, processing element `i=0` (head) *before* element `i=1` (the "prev" element) has itself been through the output-amount checks in `validatePaymentInputsAndOutputs` (`isPositiveInteger(output.amount)`): [4](#0-3) [5](#0-4) 

Because element `i=1`'s own fields are only validated when the loop reaches `i=1`, a counterparty who crafts the chain can put an `amount` field that is missing, `null`, or a non-integer string in `arrPrivateElements[1].payload.outputs[output_index]`. This value is used unchecked as `src_coin.amount` while validating the head element (`i=0`), tripping `if (!isPositiveInteger(src_coin.amount)) throw Error("no src coin amount");` — an uncaught synchronous throw fired from inside a DB-callback chain, with no `try/catch` anywhere between it and the event loop.

### Impact Explanation
This is reachable by any private-payment counterparty (e.g., someone the wallet transacts with, or anyone who can get a private chain delivered via the hub/direct connection) sending a single malformed private indivisible-asset payment chain to a wallet/light node. It matches the accepted-impact category "a node unable to confirm new units" / DoS of a node process: the receiving process crashes when `handleSavedPrivatePayments` → `privatePayment.validateAndSavePrivatePaymentChain` → `indivisibleAsset.validateAndSavePrivatePaymentChain` → `parsePrivatePaymentChain` → `validatePrivatePayment` → `validation.validatePayment` → `validatePaymentInputsAndOutputs` reaches the vulnerable branch: [6](#0-5) [7](#0-6) 

This is a repeatable, remotely triggerable crash of the victim wallet/node process from a single crafted message, causing denial of service (loss of availability to confirm/process transactions until restarted), directly analogous to the Open5GS assertion crash from a missing mandatory ASN.1 field.

### Likelihood Explanation
High/likely: the only requirement is that the attacker (recipient's private-payment counterparty) can construct/send a multi-element private payment chain for a private, fixed-denomination (indivisible) asset where a non-head chain element has a missing/invalid `amount` on the referenced output. No signatures need to be forged for the crash to trigger, because the offending element only needs to reach the point where `src_coin` is computed from unchecked untrusted JSON before its own fields are separately validated later in the loop.

### Recommendation
- In `indivisible_asset.js`’s `validatePrivatePayment`, explicitly validate `prev_hidden_output.amount` (and any other fields consumed early, such as `denomination`) with `ValidationUtils.isPositiveInteger` before using them to build `src_coin`, returning `callbacks.ifError(...)` on failure instead of letting bad data flow into `validation.js`.
- In `validation.js`, replace the `throw Error("no src_coin")/"no src_output"/"no denomination in src coin"/"no src coin amount"` assertions with a normal `cb(...)` validation error, since this code path is reachable with attacker-controlled data and must not be treated as an unreachable invariant.
- Add a defensive `try/catch` (or convert to returning errors) around the async validation chain in `parsePrivatePaymentChain`/`validatePrivatePayment` so any unexpected exception is turned into `ifError` instead of crashing the process.

### Proof of Concept
1. As a private-payment counterparty, construct a 2-element indivisible-asset private chain `[headElement, issueOrPrevElement]` for a private, `fixed_denominations` asset.
2. In `prevElement.payload.outputs[output_index]`, omit the `amount` field (or set it to `null`/a non-integer string) while keeping the other fields (`output_hash`, etc.) internally consistent enough to pass the head element's own checks in `validatePrivatePayment`.
3. Set `headElement.payload.inputs[0]` to `{type: undefined /* transfer */, unit: prevElement.unit, message_index: ..., output_index}` referencing the crafted `prevElement`.
4. Send this chain to the target wallet as a `private_payment` (e.g., via `sendPrivatePayment`/hub delivery so it lands in `unhandled_private_payments` and is processed by `handleSavedPrivatePayments`).
5. On the target, `validatePrivatePayment` copies `prev_hidden_output.amount` (undefined) into `objValidationState.src_coin.amount`; subsequent processing hits `validation.js:2423` (`if (!isPositiveInteger(src_coin.amount)) throw Error("no src coin amount");`), which is uncaught and crashes the target's Node.js process.

*Note: I was unable to fully confirm within the index whether a top-level `uncaughtException` handler exists elsewhere in the process (e.g., in a `start.js`/daemon wrapper not covered by the index) that might catch and log this instead of terminating the process outright. If such a handler exists and simply restarts/continues, the impact would be a repeated crash-loop / degraded availability rather than a single fatal crash — the recommendation to remove the `throw` and validate inputs properly still applies either way.*

### Citations

**File:** validation.js (L2151-2158)
```javascript
	for (var i=0; i<payload.outputs.length; i++){
		var output = payload.outputs[i];
		if (!isNonemptyObject(output))
			return callback("output must be a non-empty object");
		if (hasFieldsExcept(output, ["address", "amount", "blinding", "output_hash"]))
			return callback("unknown fields in payment output");
		if (!isPositiveInteger(output.amount))
			return callback("amount must be positive integer, found "+JSON.stringify(output.amount));
```

**File:** validation.js (L2412-2424)
```javascript
					// for private fixed denominations assets, we can't look up src output in the database 
					// because we validate the entire chain before saving anything.
					// Instead we prepopulate objValidationState with denomination and src_output 
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

**File:** indivisible_asset.js (L102-139)
```javascript
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

**File:** indivisible_asset.js (L198-229)
```javascript
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
```

**File:** network.js (L2467-2503)
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
							},
							// light only. Means that chain joints (excluding the head) not downloaded yet or not stable yet
							ifWaitingForChain: function(){
								console.log('waiting for chain: unit '+row.unit+', message '+row.message_index+' output '+row.output_index);
								cb();
							}
						});
```

**File:** private_payment.js (L23-119)
```javascript
function validateAndSavePrivatePaymentChain(arrPrivateElements, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("no priv elements array");
	var headElement = arrPrivateElements[0];
	if (!headElement.payload)
		return callbacks.ifError("no payload in head element");
	var asset = headElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in head element");
	if (!ValidationUtils.isNonnegativeInteger(headElement.message_index))
		return callbacks.ifError("no message index in head private element");
	
	var validateAndSave = function(){
		storage.readAsset(db, asset, null, function(err, objAsset){
			if (err)
				return callbacks.ifError(err);
			if (objAsset.is_private !== 1)
				return callbacks.ifError("asset is not private");
			if (!!objAsset.fixed_denominations !== !!headElement.payload.denomination)
				return callbacks.ifError("presence of denomination field doesn't match the asset type");
			if (!!objAsset.fixed_denominations !== ("output" in headElement))
				return callbacks.ifError("divisible asset must not have output field, indivisible must");
			db.takeConnectionFromPool(function(conn){
				conn.query("BEGIN", function(){
					var transaction_callbacks = {
						ifError: function(err){
							conn.query("ROLLBACK", function(){
								conn.release();
								callbacks.ifError(err);
							});
						},
						ifOk: function(){
							conn.query("COMMIT", function(){
								conn.release();
								callbacks.ifOk();
							});
						}
					};
					// check if duplicate
					var sql = "SELECT address, denomination, amount, blinding FROM outputs WHERE unit=? AND asset=? AND message_index=?";
					var params = [headElement.unit, asset, headElement.message_index];
					if (objAsset.fixed_denominations){
						if (!ValidationUtils.isNonnegativeInteger(headElement.output_index))
							return transaction_callbacks.ifError("no output index in head private element");
						sql += " AND output_index=?";
						params.push(headElement.output_index);
					}
					conn.query(
						sql, 
						params, 
						function(rows){
							if (rows.length > 1)
								throw Error("more than one output "+sql+' '+params.join(', '));
							if (rows.length > 0 && rows[0].address){ // we could have this output already but the address is still hidden
								const stored = rows[0];
								const payload = headElement.payload;
								let bDuplicate = false;
								if (objAsset.fixed_denominations){ // the row we selected is exactly headElement.output_index, filtered in sql above
									const claimed_output = payload.outputs?.[headElement.output_index];
									const revealed_output = headElement?.output;
									bDuplicate =
										ValidationUtils.isNonemptyObject(claimed_output)
										&& ValidationUtils.isNonemptyObject(revealed_output)
										&& stored.denomination === payload.denomination
										&& stored.amount === claimed_output.amount
										&& stored.address === revealed_output.address
										&& stored.blinding === revealed_output.blinding;
								}
								else // divisible outputs are never hidden individually and sql has no output_index filter, so match against any of them
									bDuplicate = (payload.outputs || []).some(output => {
										return ValidationUtils.isNonemptyObject(output)
											&& stored.denomination === 1
											&& stored.amount === output.amount
											&& stored.address === output.address
											&& stored.blinding === output.blinding;
									});
								if (bDuplicate) {
									console.log("duplicate private payment "+params.join(', '));
									return transaction_callbacks.ifOk();
								}
							}
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
						}
					);
				});
			});
		});
	};
	
	if (conf.bLight)
		findUnfinishedPastUnitsOfPrivateChains([arrPrivateElements], false, function(arrUnfinishedUnits){
			(arrUnfinishedUnits.length > 0) ? callbacks.ifWaitingForChain() : validateAndSave();
		});
	else
		validateAndSave();
}
```
