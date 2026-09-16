## Analysis

Searching ocore for the CVE-2023-45679 bug class — an error/allocation-failure path that fails to `return`, leaving state half-initialized while subsequent cleanup/processing code (`vorbis_deinit`) keeps operating on it — the closest reachable analog is in the private-payment handling code, which is directly triggerable by a private-payment counterparty (an unprivileged, reachable actor per the rules).

### Root cause

In `network.js`, `handleSavedPrivatePayments()` defines `validateAndSave()`: [1](#0-0) 

```js
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
    privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, { ... });
};
```

The `catch` block is exactly analogous to `start_decoder`'s early-return-on-failure path in the CVE: it recognizes the malformed input (`getBase64Hash` throws, e.g. on a payload containing invalid/malformed structures), reports the error, and already begins cleanup by calling `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` — but there is **no `return` statement** after this. Execution falls through to build `key` using the now-`undefined` `json_payload_hash`, and then unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` on the very data that just failed, exactly as `vorbis_deinit` in the CVE keeps operating on pointers left over from a `start_decoder` failure that didn't fully unwind.

### Concrete effect

Because this second call always fires, its `ifOk`/`ifError`/`ifWaitingForChain` handlers will each invoke `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` a *second time*, and the shared `async.each` iteratee callback `cb` is invoked twice for the same row: [2](#0-1) 

This double-processing means the private-payment chain that was already discarded via the error path is nonetheless pushed through `privatePayment.validateAndSavePrivatePaymentChain` → `divisible_asset.js`/`indivisible_asset.js` → `writer.saveJoint`, running a second, independent DB transaction against the same `outputs`/`inputs` rows concurrently with (or racing) the delete/cleanup path: [3](#0-2) [4](#0-3) 

This duplicated commit path for the same private output/input rows creates a race between two independent "save" flows for one private chain — one intended to be aborted, one proceeding to write — undermining the guarantee that a private payment chain is validated and persisted exactly once, and can leave the local `outputs`/`inputs` state inconsistent with what was actually accepted/rejected.

### Title
Missing `return` after catch in private-payment hash-failure path causes double-processing of a discarded private payment chain — (File: `network.js`)

### Summary
`validateAndSave()` in `network.js` (used by `handleSavedPrivatePayments`) catches a `getBase64Hash` failure on a private payment element, sends an error, and calls `deleteHandledPrivateChain(...)` — but does not `return`, so it also unconditionally runs `privatePayment.validateAndSavePrivatePaymentChain()` on the same, already-rejected chain.

### Finding Description
The `try/catch` at [5](#0-4)  mirrors the CVE-2023-45679 root cause: an error path recognizes bad/malformed input and starts cleanup, but fails to stop execution, so downstream code keeps operating on the same, now-invalid object. Here, `json_payload_hash` remains `undefined` and the code proceeds to line 2479 to call `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`, which independently re-validates and can persist the same private-payment chain via `divisible_asset.js`/`indivisible_asset.js`/`writer.saveJoint`, while the catch block has already triggered `deleteHandledPrivateChain(...)` for the same row.

### Impact Explanation
Two independent completion paths run for one `unhandled_private_payments` row: the discard/delete path and the validate-and-save path, both calling the shared `async.each` callback `cb` and both able to write to the `outputs`/`inputs` tables for the same private chain. This can corrupt local private-asset bookkeeping state (duplicate/partial writes, mismatched `is_spent` flags) for the wallet processing the chain, since the two code paths were never designed to run concurrently for the same private payment.

### Likelihood Explanation
Triggering the bug only requires a private-payment counterparty (or paired device relaying private payments) to send a private element whose `payload` causes `objectHash.getBase64Hash()` to throw (e.g. a payload containing values that fail JS well-formedness checks used elsewhere in the codebase, such as `isObjectWellFormed`). This is reachable by any device that can send private payment chains to a light wallet, requiring no special privileges.

### Recommendation
Add a `return` after the `deleteHandledPrivateChain(...)` call inside the `catch` block in `network.js` so that the fallthrough call to `privatePayment.validateAndSavePrivatePaymentChain()` (and duplicate `cb` invocation) cannot occur once the chain has already been discarded due to a hash-computation failure.

### Proof of Concept
1. Craft a private payment chain whose head element's `payload` causes `objectHash.getBase64Hash(payload, true)` to throw (e.g., a payload containing a value that fails the library's well-formedness/serialization checks).
2. Send it to a light wallet via `wallet.js`'s `handlePrivatePaymentChains` → `network.handleOnlinePrivatePayment` so it is queued into `unhandled_private_payments` and later processed by `handleSavedPrivatePayments`.
3. In `validateAndSave()`, the `catch` branch fires, sends an error result, and calls `deleteHandledPrivateChain(...)`.
4. Execution falls through (no `return`) to also call `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`, causing a second, concurrent processing pass and a duplicate `cb()` invocation for the same row. [6](#0-5)

### Citations

**File:** network.js (L2467-2504)
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
					};
```

**File:** divisible_asset.js (L17-76)
```javascript
function validateAndSavePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	// we always have only one element
	validateAndSaveDivisiblePrivatePayment(conn, arrPrivateElements[0], callbacks);
}


function validateAndSaveDivisiblePrivatePayment(conn, objPrivateElement, callbacks){
	validateDivisiblePrivatePayment(conn, objPrivateElement, {
		ifError: callbacks.ifError,
		ifOk: function(bStable, arrAuthorAddresses){
			console.log("private validation OK "+bStable);
			var unit = objPrivateElement.unit;
			var message_index = objPrivateElement.message_index;
			var payload = objPrivateElement.payload;
			var arrQueries = [];
			for (var j=0; j<payload.outputs.length; j++){
				var output = payload.outputs[j];
				conn.addQuery(arrQueries, 
					"INSERT INTO outputs (unit, message_index, output_index, address, amount, blinding, asset) VALUES (?,?,?,?,?,?,?)",
					[unit, message_index, j, output.address, parseInt(output.amount), output.blinding, payload.asset]
				);
			}
			for (var j=0; j<payload.inputs.length; j++){
				var input = payload.inputs[j];
				var type = input.type || "transfer";
				var src_unit = input.unit;
				var src_message_index = input.message_index;
				var src_output_index = input.output_index;
				var address = null, address_sql = null;
				if (type === "issue")
					address = input.address || arrAuthorAddresses[0];
				else{ // transfer
					if (arrAuthorAddresses.length === 1)
						address = arrAuthorAddresses[0];
					else
						address_sql = "(SELECT address FROM outputs \
						WHERE unit="+conn.escape(src_unit)+" AND message_index="+conn.escape(src_message_index)+" \
							AND output_index="+conn.escape(src_output_index)+" AND address IN("+conn.escape(arrAuthorAddresses)+"))";
				}
				var is_unique = bStable ? 1 : null; // unstable still have chances to become nonserial therefore nonunique
				conn.addQuery(arrQueries, "INSERT INTO inputs \n\
						(unit, message_index, input_index, type, \n\
						src_unit, src_message_index, src_output_index, \
						serial_number, amount, \n\
						asset, is_unique, address) VALUES(?,?,?,?,?,?,?,?,?,?,?,"+(address_sql || conn.escape(address))+")",
					[unit, message_index, j, type, 
					 src_unit, src_message_index, src_output_index, 
					 input.serial_number, input.amount, 
					 payload.asset, is_unique]);
				if (type === "transfer"){
					conn.addQuery(arrQueries, 
						"UPDATE outputs SET is_spent=1 WHERE unit=? AND message_index=? AND output_index=?",
						[src_unit, src_message_index, src_output_index]);
				}
			}
			async.series(arrQueries, callbacks.ifOk);
		}
	});
}

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
