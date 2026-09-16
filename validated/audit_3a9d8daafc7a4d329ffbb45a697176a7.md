### Title
Unbounded private-payment chain length allows memory-exhaustion DoS on receiving node - ([File: network.js])

### Summary
CVE-2016-6172 describes PowerDNS crashing/exhausting memory because it placed no bound on the size of an AXFR/IXFR response it accepted from a peer before processing it. The analogous weak point in `ocore--009` is the handling of private-payment chains (`arrPrivateElements`/`arrChains`) sent by a private-payment counterparty: the chain array length is never capped anywhere in the receive path, so a counterparty can hand a wallet an arbitrarily long chain and force it to be fully buffered, `JSON.stringify`'d, cached, and recursively validated/queried element-by-element.

### Finding Description
`network.handleOnlinePrivatePayment` only checks that `arrPrivateElements` is a non-empty array; it never bounds its `.length`: [1](#0-0) 
The whole array is then serialized and stored verbatim (`JSON.stringify(arrPrivateElements)` into `unhandled_private_payments`, and separately kept in memory via `savePrivatePayment`), with no size limit check anywhere in the call chain: [2](#0-1) 

The wallet-level entry point `handlePrivatePaymentChains` (reached from a paired device / private-payment counterparty message) validates only the *shape* of each chain element, never the number of elements per chain nor the number of chains, before invoking `network.handleOnlinePrivatePayment` for each one: [3](#0-2) [4](#0-3) 
The generic anti-nesting/anti-flood guard `isTooDeeplyNestedOrHasTooManyNodes()` used elsewhere (e.g. for hub messages, posted joints, device messages) is never applied to `body.chains` in `handlePrivatePaymentChains`, nor to `arrPrivateElements` in `handleOnlinePrivatePayment`, unlike other untrusted-payload entry points such as `handleMessageFromHub` (`isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000)`): [5](#0-4) 

Once the chain is accepted, `indivisible_asset.parsePrivatePaymentChain`/`validateAndSavePrivatePaymentChain` and `private_payment.validateAndSavePrivatePaymentChain` iterate over every element of `arrPrivateElements` with `async.forEachOfSeries`, performing per-element DB queries, hashing, and building SQL query arrays, all sized proportionally to the (attacker-controlled, unbounded) chain length: [6](#0-5) [7](#0-6) 
`private_payment.js`'s top-level dispatcher likewise never checks the chain length before dispatching to the asset-specific handlers: [8](#0-7) 

None of `constants.js`'s anti-spam limits (`MAX_INPUTS_PER_PAYMENT_MESSAGE`, `MAX_OUTPUTS_PER_PAYMENT_MESSAGE`, `MAX_SPEND_PROOFS_PER_MESSAGE`, etc.) bound the *chain length* of a private-payment (only per-message input/output counts), so this class of attack surface is structurally uncovered: [9](#0-8) 

### Impact Explanation
A malicious private-payment counterparty (or a device paired with the victim) can send a `private_payment_chains` device message, or a raw `private_payment`/`just_saying` payload, containing an arrPrivateElements/chains array with an extremely large number of synthetic elements (each minimally-shaped to pass the per-element `isNonemptyObject`/`isNonemptyString` checks in `handlePrivatePaymentChains`). This forces the receiving node/wallet to:
- Buffer and `JSON.stringify` the entire array into `unhandled_private_payments` and in-memory caches,
- Run unbounded `async.forEachOfSeries` loops with a DB query per element,
- Repeatedly `_.cloneDeep` the whole chain (`indivisible_asset.js` line 885 via `getSavingCallbacks`),

consuming memory and CPU disproportionate to any legitimate payment and potentially causing the wallet/light node process to run out of memory or become unresponsive — a denial-of-service against the counterparty's node, matching the "network unable to confirm new units" / node-availability class of impact this scan is scoped to accept.

### Likelihood Explanation
Any device paired with the victim (a normal precondition for private-asset payments) can trigger this without needing a valid asset, valid spend proofs, or any spend of real funds — the length/shape checks that exist (`isNonemptyArray`, `isNonemptyObject`, `isNonemptyString` on required fields) are all satisfiable by a small amount of junk data replicated many times. No stability, signature, or fee requirement gates the initial buffering and iteration cost, making this trivially and repeatedly triggerable.

### Recommendation
Add an explicit, low anti-spam cap (e.g. similar in spirit to `MAX_SPEND_PROOFS_PER_MESSAGE` = 128) on:
1. The number of chains in `body.chains` and the number of elements per chain in `wallet.handlePrivatePaymentChains`, rejecting oversized submissions before any further processing.
2. `arrPrivateElements.length` at the very top of `network.handleOnlinePrivatePayment` and `private_payment.validateAndSavePrivatePaymentChain`, mirroring the existing `isTooDeeplyNestedOrHasTooManyNodes` guard pattern used for other untrusted inputs (hub messages, device messages, posted joints).
3. Apply `isTooDeeplyNestedOrHasTooManyNodes` (or an equivalent length/size check) to the whole `body.chains` object early in `handlePrivatePaymentChains`, before it is hashed/cached/dispatched.

### Proof of Concept
1. Pair a malicious device with the victim's wallet (a normal, low-privilege step for private-payment counterparties).
2. Send a `private_payment_chains` message whose `body.chains` contains, e.g., 1 chain with 500,000 synthetic elements, each element minimally satisfying the shape checks in `wallet.js` lines 959-972 (non-empty unit string, non-empty payload object with `asset`, non-empty `inputs`/`outputs` arrays of non-empty objects).
3. Observe that `handlePrivatePaymentChains` accepts and forwards the entire array to `network.handleOnlinePrivatePayment` without any length check, which serializes/caches the whole array and (for indivisible assets) recursively iterates every element via `async.forEachOfSeries`, driving up memory and CPU on the receiving node/wallet well beyond what any legitimate chain would require.

### Citations

**File:** network.js (L2376-2379)
```javascript
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
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

**File:** wallet.js (L64-66)
```javascript
function handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, callbacks){
	if (isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000))
		return callbacks.ifError("message from hub is too deeply nested or has too many nodes");
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

**File:** wallet.js (L1020-1035)
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

**File:** indivisible_asset.js (L239-296)
```javascript
function validateAndSavePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	parsePrivatePaymentChain(conn, arrPrivateElements, {
		ifError: callbacks.ifError,
		ifOk: function(bAllStable){
			console.log("saving private chain "+JSON.stringify(arrPrivateElements));
			profiler.start();
			var arrQueries = [];
			for (var i=0; i<arrPrivateElements.length; i++){
				var objPrivateElement = arrPrivateElements[i];
				var payload = objPrivateElement.payload;
				var input_address = objPrivateElement.input_address;
				var input = payload.inputs[0];
				var is_unique = objPrivateElement.bStable ? 1 : null; // unstable still have chances to become nonserial therefore nonunique
				if (!input.type) // transfer
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO inputs \n\
						(unit, message_index, input_index, src_unit, src_message_index, src_output_index, asset, denomination, address, type, is_unique) \n\
						VALUES (?,?,?,?,?,?,?,?,?,'transfer',?)", 
						[objPrivateElement.unit, objPrivateElement.message_index, 0, input.unit, input.message_index, input.output_index, 
						payload.asset, payload.denomination, input_address, is_unique]);
				else if (input.type === 'issue')
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO inputs \n\
						(unit, message_index, input_index, serial_number, amount, asset, denomination, address, type, is_unique) \n\
						VALUES (?,?,?,?,?,?,?,?,'issue',?)", 
						[objPrivateElement.unit, objPrivateElement.message_index, 0, input.serial_number, input.amount, 
						payload.asset, payload.denomination, input_address, is_unique]);
				else
					throw Error("neither transfer nor issue after validation");
				var is_serial = objPrivateElement.bStable ? 1 : null; // initPrivatePaymentValidationState already checks for non-serial
				var outputs = payload.outputs;
				for (var output_index=0; output_index<outputs.length; output_index++){
					var output = outputs[output_index];
					console.log("inserting output "+JSON.stringify(output));
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO outputs \n\
						(unit, message_index, output_index, amount, output_hash, asset, denomination) \n\
						VALUES (?,?,?,?,?,?,?)",
						[objPrivateElement.unit, objPrivateElement.message_index, output_index, 
						output.amount, output.output_hash, payload.asset, payload.denomination]);
					var fields = "is_serial=?";
					var params = [is_serial];
					if (output_index === objPrivateElement.output_index){
						var is_spent = (i===0) ? 0 : 1;
						fields += ", is_spent=?, address=?, blinding=?";
						params.push(is_spent, objPrivateElement.output.address, objPrivateElement.output.blinding);
					}
					params.push(objPrivateElement.unit, objPrivateElement.message_index, output_index);
					conn.addQuery(arrQueries, "UPDATE outputs SET "+fields+" WHERE unit=? AND message_index=? AND output_index=? AND is_spent=0", params);
				}
			}
		//	console.log("queries: "+JSON.stringify(arrQueries));
			async.series(arrQueries, function(){
				profiler.stop('save');
				callbacks.ifOk();
			});
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
