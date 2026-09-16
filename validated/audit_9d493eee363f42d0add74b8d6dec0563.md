### Title
Uncontrolled Resource Consumption via Unbounded Private-Payment Chains/Batches - (File: wallet.js, network.js, indivisible_asset.js)

### Summary
An unprivileged private-payment counterparty (a wallet device correspondent) can send a `private_payments` message containing an arbitrarily large number of chains, each containing an arbitrarily long array of private elements. Neither the size of `body.chains` nor the length of any individual chain is bounded anywhere in the validation path before expensive, serialized, per-element database work (spend-proof lookups, `graph.determineIfIncluded`, full `validatePayment`) is performed on every element.

### Finding Description
`handlePrivatePaymentChains` in [1](#0-0)  only validates that `arrChains` is a non-empty array and that each chain element is a well-formed object (has a unit, payload, inputs, outputs). It never checks `arrChains.length` or the length of any individual `c` (the chain array).

Each chain is then handed to `network.handleOnlinePrivatePayment` via `async.eachSeries` [2](#0-1) , which in turn calls `privatePayment.validateAndSavePrivatePaymentChain` [3](#0-2) . For indivisible (fixed-denomination) assets this dispatches to `indivisible_asset.js`'s `validateAndSavePrivatePaymentChain` → `parsePrivatePaymentChain`, which iterates the *entire* `arrPrivateElements` array with `async.forEachOfSeries`, and for **every** element performs a `validatePrivatePayment` call that issues multiple sequential DB queries (`spend_proofs` lookup, `graph.determineIfIncluded`, and a full `validation.validatePayment` pass) [4](#0-3) [5](#0-4) .

None of `wallet.js`, `network.js`'s `handleOnlinePrivatePayment` [6](#0-5) , or `private_payment.js` impose any maximum on:
- the number of chains in a single `private_payments` message, or
- the number of elements (hops) in a single chain.

By contrast, the codebase is otherwise very careful about bounding attacker-influenced work: units are capped by `MAX_MESSAGES_PER_UNIT`, `MAX_AUTHORS_PER_UNIT`, `isTooDeeplyNestedOrHasTooManyNodes`, AA execution is capped by `MAX_RESPONSES_PER_PRIMARY_TRIGGER`/`MAX_OPS`/`MAX_COMPLEXITY` [7](#0-6) , formula recursion is capped at depth 100 [8](#0-7) . The private-payment chain/batch path is a conspicuous exception with no analogous anti-spam limit, which is the same bug class as the CVE (an authenticated-but-unprivileged actor able to force unbounded server-side resource consumption by supplying an unbounded quantity of "items"—coupons in the Adobe case, private-payment chain elements here).

### Impact Explanation
A malicious correspondent/counterparty (someone the victim has merely exchanged a device address with, e.g., any contact in their wallet, which requires only low privilege — much like the CVE's "high-privileged" Adobe admin analog maps to a low-bar authenticated correspondent in ocore) can send a single `private_payments` device message containing thousands of chains, each with thousands of forged-looking but well-formed elements. This drives the victim's wallet/hub into performing a very large number of serialized DB queries and full payment-validation passes in `async.eachSeries`/`async.forEachOfSeries`, exhausting CPU/DB connections and event-loop time, causing the wallet or hub process to slow to a crawl or become unresponsive (denial-of-service), matching "high-usage of resources" impact.

### Likelihood Explanation
Likelihood is high: crafting a `private_payments` body only requires satisfying the loose shape checks (`isNonemptyObject`, presence of `unit`, `payload.asset`, `payload.inputs`, `payload.outputs`); the attacker does not need valid signatures or real spend proofs to get the array iterated—each element only fails validation *after* the expensive queries are made. Any device correspondent (a pairing that is easy to obtain, e.g., via a pairing link) can trigger this without any special privilege beyond being paired, and it can be repeated at will.

### Recommendation
Impose explicit anti-spam limits analogous to `constants.MAX_MESSAGES_PER_UNIT`/`MAX_INPUTS_PER_PAYMENT_MESSAGE`, e.g.:
- Reject `handlePrivatePaymentChains` bodies where `arrChains.length` exceeds a small bound (e.g., 100).
- Reject any chain `c` whose `c.length` exceeds a reasonable maximum hop count (e.g., 100), both in `wallet.js`'s `handlePrivatePaymentChains` and in `network.js`'s `handleOnlinePrivatePayment`/`private_payment.js`'s `validateAndSavePrivatePaymentChain`, before any DB work is performed.
- Consider adding a per-device-address rate limit on the number of private-payment validations processed per unit time.

### Proof of Concept
1. Attacker pairs as a device correspondent with the victim's wallet (normal, low-privilege pairing).
2. Attacker sends a `private_payments` message over the paired encrypted channel with `body.chains` containing, e.g., 10,000 chains, each chain containing 500 synthetically well-formed private elements (each satisfying only the shallow `isNonemptyObject`/field-presence checks in [9](#0-8) , with fabricated `unit`/`payload` hashes chained together consistently so they pass the shape checks).
3. The victim's `handlePrivatePaymentChains` iterates all chains serially, and for each chain `parsePrivatePaymentChain`/`validatePrivatePayment` fires multiple sequential DB queries per element.
4. The resulting volume of queries (chains × elements × queries-per-element) saturates the victim's DB connection pool and event loop, degrading or halting service for legitimate traffic — reproducing the "force high resource usage" pattern described in CVE-2024-20716, adapted to ocore's private-payment chain-processing code path.

**Note on completeness:** I was not able to fully trace whether any upstream device-message-size cap (e.g., in `device.js`/pairing transport) indirectly limits the total payload size before it reaches `handlePrivatePaymentChains`; if such a limit exists and is small enough, it could partially mitigate but likely still allows a chain long/wide enough to cause meaningful load, since no explicit chain-count or chain-length limit was found in the reachable validation code.

### Citations

**File:** wallet.js (L955-982)
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
	if (handledChainsCache[cache_key]) {
		eventBus.emit('all_private_payments_handled', from_address);
		eventBus.emit('all_private_payments_handled-' + arrChains[0][0].unit);
		return callbacks.ifOk();
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

**File:** private_payment.js (L23-118)
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
```

**File:** indivisible_asset.js (L20-182)
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
			}
			else if (input.type === 'issue'){
				if (objPrevPrivateElement)
					return callbacks.ifError("prev payload and initial input");

				input_address = (objPartialUnit.authors.length === 1) ? objPartialUnit.authors[0].address : input.address;
				try {
					spend_proof = objectHash.getBase64Hash({
						asset: payload.asset,
						address: input_address,
						serial_number: input.serial_number, // need to avoid duplicate spend proofs when issuing uncapped coins
						denomination: payload.denomination,
						amount: input.amount
					});
				}
				catch (e) {
					return callbacks.ifError("failed to calc issue spend proof: " + e.message);
				}
			}
			else
				return callbacks.ifError("neither transfer nor issue in private input");
			
			if (!objPartialUnit.authors.some(function(author){ return (author.address === input_address); }))
				return callbacks.ifError("input address not found among unit authors");

			arrFuncs.push(function(cb){
				validateSpendProof(spend_proof, cb);
			});
			arrFuncs.push(function(cb){
				// we need to unhide the single output we are interested in, other outputs stay partially hidden like {amount: 300, output_hash: "base64"}
				var partially_revealed_payload = _.cloneDeep(payload);
				var our_output = partially_revealed_payload.outputs[objPrivateElement.output_index];
				our_output.address = objPrivateElement.output.address;
				our_output.blinding = objPrivateElement.output.blinding;
				validation.validatePayment(conn, partially_revealed_payload, objPrivateElement.message_index, objPartialUnit, objValidationState, cb);
			});
			async.series(arrFuncs, function(err){
			//	profiler.stop('validatePayment');
				err ? callbacks.ifError(err) : callbacks.ifOk(bStable, input_address);
			});
		}
	);
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

**File:** constants.js (L42-70)
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

exports.MAX_PROFILE_FIELD_LENGTH = 50;
exports.MAX_PROFILE_VALUE_LENGTH = 100;

exports.MAX_AA_STRING_LENGTH = 4096;
exports.MAX_STATE_VAR_NAME_LENGTH = 128;
exports.MAX_STATE_VAR_VALUE_LENGTH = 1024;
exports.MAX_OPS = process.env.MAX_OPS || 2000;
exports.MAX_RESPONSES_PER_PRIMARY_TRIGGER = process.env.MAX_RESPONSES_PER_PRIMARY_TRIGGER || 10;
exports.MAX_RESPONSE_VARS_LENGTH = 4000;
exports.MAX_SIGNED_PACKAGES_PER_AA_EVAL = 3;
```

**File:** formula/validation.js (L284-288)
```javascript
			}
			orig_cb(err);
		};
		if (depth > 100 && (mci >= constants.pemCurvesFixMci || require('../storage.js').getMinRetrievableMci() >= constants.pemCurvesFixMci))
			return cb("maximum depth exceeded");
```
