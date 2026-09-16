### Title
Unbounded private-payment chain length allows resource-exhaustion DoS on receiving wallet/hub - ([File: wallet.js])

### Summary
The `hub/message` → `private_payments` code path lets any paired device send an arbitrary number of private-payment "chains", each containing an arbitrary number of chain elements, with only a generic node/depth cap (`isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000)`) and no dedicated limit on the number of elements per chain or the number of chains per message. This mirrors CVE-2026-66277's root cause — a protocol that lacks a specific cap on the number of sub-units ("frames") that make up a single logical delivery — and lets a counterparty force the victim to perform unbounded serial DB work per incoming private payment.

### Finding Description
`handlePrivatePaymentChains` in [1](#0-0)  only validates that `body.chains` is a non-empty array of non-empty arrays of well-formed elements — it never checks `arrChains.length` or the length of any individual chain (`c.length`). The only prior gate is the generic `isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000)` check in `handleMessageFromHub` [2](#0-1) , which limits total JSON node count/depth but does not bound the number of *chain elements*, each of which triggers expensive, serial, per-element work.

Each chain is processed with `async.eachSeries` calling `network.handleOnlinePrivatePayment` for every top-level chain [3](#0-2) , which in turn calls `privatePayment.validateAndSavePrivatePaymentChain` [4](#0-3) . That function performs a DB transaction, asset lookup, and duplicate-check query [5](#0-4) , then dispatches to `indivisibleAsset`/`divisibleAsset`'s `validateAndSavePrivatePaymentChain`, which calls `parsePrivatePaymentChain` — an `async.forEachOfSeries` over **every element of the chain**, each doing its own `validatePrivatePayment` (spend-proof hash computation, `validation.validatePayment` full payment validation, and DB queries) [6](#0-5) . There is no `constants.MAX_*` cap analogous to `MAX_MESSAGES_PER_UNIT` or `MAX_SPEND_PROOFS_PER_MESSAGE` limiting the chain length or number of chains, unlike ordinary unit validation which explicitly bounds message/spend-proof counts [7](#0-6) .

Because a chain element only needs to satisfy shallow shape checks (`isNonemptyObject`, has `unit`/`payload.asset`/`inputs`/`outputs`) to pass the initial filter in `handlePrivatePaymentChains` [8](#0-7) , an attacker (any paired/correspondent device acting as a private-payment counterparty) can construct one or many chains with a very large number of elements (bounded only by the 100,000-node/20-depth generic limit, which for shallow small objects still permits thousands of elements) and repeatedly send `private_payments` messages, forcing the victim's node to perform thousands of serial DB round-trips, hash computations and full payment validations per message.

### Impact Explanation
This does not directly cause fund loss, but it lets an authenticated counterparty (already paired to the victim device) trigger sustained CPU and DB load on the victim's wallet/hub, degrading responsiveness or causing a denial of service, analogous to the Proton-J issue where an authenticated peer could exhaust resources by controlling the number of "frames" per delivery. Given the constraint that only Medium/High/Critical, concrete-impact analogs are acceptable, and this analog produces resource exhaustion rather than fund loss or consensus disagreement, it lands at Medium severity — consistent with the CVE's own CVSS 6.5 rating.

### Likelihood Explanation
Likelihood is high for any node that accepts private payments from paired devices (wallets, hubs relaying `private_payments`), since the sender only needs to be a correspondent device (a normal precondition for wallet interactions such as receiving a payment or textcoin), and no special privilege beyond pairing is required.

### Recommendation
Add explicit limits (comparable to `MAX_MESSAGES_PER_UNIT`) on:
1. The number of chains allowed per `private_payments` message (`body.chains.length`).
2. The number of elements allowed per chain (`c.length`) in `handlePrivatePaymentChains` before any DB work is performed, and equivalently in `network.handleOnlinePrivatePayment` / `parsePrivatePaymentChain`.
Reject messages exceeding these limits immediately with `callbacks.ifError`, before queuing to `unhandled_private_payments` or beginning validation.

### Proof of Concept
A paired device sends a `private_payments` justsaying/message whose `body.chains` contains many chains, each an array of many well-formed-looking but ultimately invalid chain elements (e.g., referencing a valid `asset` and syntactically valid `inputs`/`outputs` but failing deeper validation). This passes the shallow checks in `handlePrivatePaymentChains` [8](#0-7)  and the generic node-count check in `handleMessageFromHub` [9](#0-8) , then causes `parsePrivatePaymentChain` to iterate serially over every element, performing a DB query and full payment validation for each [10](#0-9) , consuming CPU/DB resources proportional to the attacker-chosen chain length with no dedicated cap.

### Citations

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

**File:** network.js (L2412-2429)
```javascript
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
```

**File:** private_payment.js (L35-105)
```javascript
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
```

**File:** indivisible_asset.js (L187-236)
```javascript
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

**File:** constants.js (L42-56)
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
```
