## Title
Unbounded-length private payment chain can be crafted by any private-payment counterparty and causes serialized, mutex-blocking validation, stalling unit processing - (File: private_payment.js, indivisible_asset.js, wallet.js)

### Summary
The chain of private-payment elements (`arrPrivateElements` / `arrChains`) that a counterparty sends over a device (wallet) channel or peer-to-peer (`private_payment`) message has no maximum-length check anywhere in the validation pipeline. A malicious payer can build an artificially long chain of tiny private transfers and, when finally paying the victim, submit the whole chain in one `private_payment_chains` device message. The victim's node/wallet must walk and validate the entire chain sequentially, one DB round-trip per element, while holding a global mutex, so an attacker-controlled array size directly determines how long the node is blocked from doing anything else (analogous to the reported `deposits` array being scanned without a bound in `netAtPrice()`/`depositAuction()`).

### Finding Description
Private payment chains are represented as `arrPrivateElements`, an array whose length equals the number of transfer hops between the original issuance and the final output. Nothing in the codebase limits how many hops such a chain may contain:

- `handlePrivatePaymentChains()` in `wallet.js` only validates the *shape* of each chain element (non-empty objects/strings), never its length: [1](#0-0) 
- `validateAndSavePrivatePaymentChain()` in `private_payment.js` accepts any non-empty array and hands it straight to per-asset processing: [2](#0-1) 
- `parsePrivatePaymentChain()` in `indivisible_asset.js` walks the *entire* array with `async.forEachOfSeries`, issuing a `validatePrivatePayment` (itself doing multiple DB queries) for every single element, with no cap on `arrPrivateElements.length`: [3](#0-2) 
- `buildPrivateElementsChain()` recursively walks the input chain one DB query at a time (`readPayloadAndGoUp`), again with no depth limit, used both when composing (`getSavingCallbacks`) and when restoring/serving chains (`restorePrivateChains`): [4](#0-3) 

By contrast, every other array that is validated as part of a *unit* (inputs, outputs, messages, authors, parents, data feeds, etc.) has an explicit anti-spam cap in `constants.js` (`MAX_INPUTS_PER_PAYMENT_MESSAGE`, `MAX_OUTPUTS_PER_PAYMENT_MESSAGE`, `MAX_MESSAGES_PER_UNIT`, `MAX_PARENTS_PER_UNIT`, `MAX_AUTHORS_PER_UNIT`, `MAX_DATA_FEEDS_PER_MESSAGE`, etc.): [5](#0-4)  and `MAX_RESPONSES_PER_PRIMARY_TRIGGER` bounds AA response chains: [6](#0-5) . The private-payment chain array is the one array of this kind that received no equivalent bound.

Critically, this validation runs while holding a global mutex that also guards ordinary unit validation/writing: `getSavingCallbacks` in `indivisible_asset.js` acquires the `'handleJoint'` mutex before calling `validation.validate`, and the private-chain building/saving (`buildPrivateElementsChain` + `validateAndSavePrivatePaymentChain`) happens inside the resulting `preCommitCallback`, i.e. still under that lock: [7](#0-6) . On the receiving side, `network.js` similarly serializes chain handling under the `'saved_private'` / `'private_chains'` mutexes: [8](#0-7) , [9](#0-8) .

### Impact Explanation
Because the chain length is entirely attacker-controlled (an attacker just needs to perform N cheap tiny transfers of a private asset to himself before finally paying the victim) and each element requires several sequential, un-batched DB reads/writes, a sufficiently long chain (thousands of hops) makes `parsePrivatePaymentChain`/`buildPrivateElementsChain` run for an extended, linearly-growing time while holding `handleJoint`/`saved_private`/`private_chains` mutexes. Since these mutexes are shared with normal unit validation and joint saving, this stalls the victim's ability to validate/accept *any* new unit for the duration of the walk — a concrete denial of service against the node's ability to confirm new units, consistent with the required impact bar (network/node unable to confirm new units). For a light wallet this can hang the wallet indefinitely and repeatedly (the message is retried via `handleSavedPrivatePayments`/`requestUnfinishedPastUnitsOfSavedPrivateElements` timers), for a full node acting as a hub/relay for private payments it can degrade service for all users behind it.

### Likelihood Explanation
Any user who can transact with the victim over a private asset (a private-payment counterparty, explicitly an unprivileged/reachable actor) can build this chain purely by making ordinary, valid transfers to their own addresses — no protocol violation or malicious peer/hub behavior is required, only patience/cost to build the chain length, and the fees for tiny private transfers are low. No existing limit prevents this, making the likelihood high once discovered.

### Recommendation
Introduce and enforce an explicit maximum chain length (e.g. a new `constants.MAX_PRIVATE_CHAIN_LENGTH`) checked as early as possible:
- In `handlePrivatePaymentChains()` (wallet.js) and `handleOnlinePrivatePayment()` (network.js), reject `arrPrivateElements`/`arrChains` whose length exceeds the cap before any DB work is performed.
- In `parsePrivatePaymentChain()`/`validateDivisiblePrivatePayment()` (indivisible_asset.js / divisible_asset.js), likewise bail out early if `arrPrivateElements.length` is too large.
- In `buildPrivateElementsChain()`, add a depth counter and abort once the cap is exceeded, so that long-lived recursion cannot be produced even during composing/serving of chains.
- Consider moving chain validation for very long chains outside of the `handleJoint`/`saved_private` mutex scope, or processing in bounded batches, to reduce the blast radius even if a legitimate long chain occurs.

### Proof of Concept
1. Attacker creates a private (indivisible or divisible) asset transfer chain to himself with N (e.g. 5,000) hops: issue → transfer → transfer → … → transfer, each hop a minimal, valid unit.
2. Attacker performs the final transfer of that same output to the victim and sends the resulting `arrPrivateElements` (length N) to the victim via the wallet device protocol (`private_payment_chains`) as handled by `handlePrivatePaymentChains()`.
3. The victim's node/wallet calls `validateAndSavePrivatePaymentChain` → `parsePrivatePaymentChain`, which iterates all N elements sequentially, each requiring `initPrivatePaymentValidationState` plus additional queries, while holding the `handleJoint`/`saved_private` mutex.
4. During this time, the victim's node cannot validate or write any other joint, effectively freezing new-unit processing until the full N-element chain finishes validating — demonstrating the unbounded-array DoS.

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

**File:** private_payment.js (L23-34)
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

**File:** indivisible_asset.js (L619-721)
```javascript
function buildPrivateElementsChain(conn, unit, message_index, output_index, payload, handlePrivateElements){
	var asset = payload.asset;
	var denomination = payload.denomination;
	var output = payload.outputs[output_index];
	var hidden_payload = _.cloneDeep(payload);
	hidden_payload.outputs.forEach(function(o){
		delete o.address;
		delete o.blinding;
		// output_hash was already added
	});
	var arrPrivateElements = [{
		unit: unit,
		message_index: message_index,
		payload: hidden_payload,
		output_index: output_index,
		output: {
			address: output.address,
			blinding: output.blinding
		}
	}];
	
	function readPayloadAndGoUp(_unit, _message_index, _output_index){
		conn.query(
			"SELECT src_unit, src_message_index, src_output_index, serial_number, denomination, amount, address, asset, \n\
				(SELECT COUNT(*) FROM unit_authors WHERE unit=?) AS count_authors \n\
			FROM inputs WHERE unit=? AND message_index=?", 
			[_unit, _unit, _message_index],
			function(in_rows){
				if (in_rows.length === 0)
					throw Error("building chain: blackbyte input not found");
				if (in_rows.length > 1)
					throw Error("building chain: more than 1 input found");
				var in_row = in_rows[0];
				if (!in_row.address)
					throw Error("readPayloadAndGoUp: input address is NULL");
				if (in_row.asset !== asset)
					throw Error("building chain: asset mismatch");
				if (in_row.denomination !== denomination)
					throw Error("building chain: denomination mismatch");
				var input = {};
				if (in_row.src_unit){ // transfer
					input.unit = in_row.src_unit;
					input.message_index = in_row.src_message_index;
					input.output_index = in_row.src_output_index;
				}
				else{
					input.type = 'issue';
					input.serial_number = in_row.serial_number;
					input.amount = in_row.amount;
					if (in_row.count_authors > 1)
						input.address = in_row.address;
				}
				conn.query(
					"SELECT address, blinding, output_hash, amount, output_index, asset, denomination FROM outputs \n\
					WHERE unit=? AND message_index=? ORDER BY output_index", 
					[_unit, _message_index], 
					function(out_rows){
						if (out_rows.length === 0)
							throw Error("blackbyte output not found");
						var output = {};
						var outputs = out_rows.map(function(o){
							if (o.asset !== asset)
								throw Error("outputs asset mismatch");
							if (o.denomination !== denomination)
								throw Error("outputs denomination mismatch");
							if (o.output_index === _output_index){
								output.address = o.address;
								output.blinding = o.blinding;
							}
							return {
								amount: o.amount,
								output_hash: o.output_hash
							};
						});
						if (!output.address)
							throw Error("output not filled");
						var objPrivateElement = {
							unit: _unit,
							message_index: _message_index,
							payload: {
								asset: asset,
								denomination: denomination,
								inputs: [input],
								outputs: outputs
							},
							output_index: _output_index,
							output: output
						};
						arrPrivateElements.push(objPrivateElement);
						(input.type === 'issue') 
							? handlePrivateElements(arrPrivateElements)
							: readPayloadAndGoUp(input.unit, input.message_index, input.output_index);
					}
				);
			}
		);
	}
	
	var input = payload.inputs[0];
	(input.type === 'issue') 
		? handlePrivateElements(arrPrivateElements)
		: readPayloadAndGoUp(input.unit, input.message_index, input.output_index);
}
```

**File:** indivisible_asset.js (L826-900)
```javascript
function getSavingCallbacks(to_address, callbacks){
	return {
		ifError: callbacks.ifError,
		ifNotEnoughFunds: callbacks.ifNotEnoughFunds,
		ifOk: async function(objJoint, assocPrivatePayloads, composer_unlock){
			var objUnit = objJoint.unit;
			var unit = objUnit.unit;
			const validate_and_save_unlock = await mutex.lock('handleJoint');
			const combined_unlock = () => {
				validate_and_save_unlock();
				composer_unlock();
			};
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
					var bPrivate = !!assocPrivatePayloads;
					var arrRecipientChains = bPrivate ? [] : null; // chains for to_address
					var arrCosignerChains = bPrivate ? [] : null; // chains for all output addresses, including change, to be shared with cosigners (if any)
					var preCommitCallback = null;
					var bPreCommitCallbackFailed = false;
					
					if (bPrivate){
						preCommitCallback = function(conn, cb){
							async.eachSeries(
								Object.keys(assocPrivatePayloads),
								function(payload_hash, cb2){
									var message_index = composer.getMessageIndexByPayloadHash(objUnit, payload_hash);
									var payload = assocPrivatePayloads[payload_hash];
									// We build, validate, and save two chains: one for the payee, the other for oneself (the change).
									// They differ only in the last element
									async.forEachOfSeries(
										payload.outputs,
										function(output, output_index, cb3){
											// we have only heads of the chains so far. Now add the tails.
											buildPrivateElementsChain(
												conn, unit, message_index, output_index, payload, 
												function(arrPrivateElements){
													validateAndSavePrivatePaymentChain(conn, _.cloneDeep(arrPrivateElements), {
														ifError: function(err){
															cb3(err);
														},
														ifOk: function(){
															if (output.address === to_address)
																arrRecipientChains.push(arrPrivateElements);
															arrCosignerChains.push(arrPrivateElements);
															cb3();
														}
													});
												}
											);
										},
										cb2
									);
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

**File:** constants.js (L68-68)
```javascript
exports.MAX_RESPONSES_PER_PRIMARY_TRIGGER = process.env.MAX_RESPONSES_PER_PRIMARY_TRIGGER || 10;
```

**File:** network.js (L2444-2521)
```javascript
function handleSavedPrivatePayments(unit){
	//if (unit && assocUnitsInWork[unit])
	//    return;
	if (!my_device_address) return; // skip if we don't have a wallet
	if (!unit && mutex.isAnyOfKeysLocked(["private_chains"])) // we are still downloading the history (light)
		return console.log("skipping handleSavedPrivatePayments because history download is still under way");
	var lock = unit ? mutex.lock : mutex.lockOrSkip;
	lock(["saved_private"], function(unlock){
		var sql = unit
			? "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments WHERE unit="+db.escape(unit)
			: "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments CROSS JOIN units USING(unit)";
		db.query(sql, function(rows){
			if (rows.length === 0)
				return unlock();
			var assocNewUnits = {};
			async.each( // handle different chains in parallel
				rows,
				function(row, cb){
					var arrPrivateElements = JSON.parse(row.json);
					var ws = getPeerWebSocket(row.peer);
					if (ws && ws.readyState !== ws.OPEN)
						ws = null;
					
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
					
					if (conf.bLight && arrPrivateElements.length > 1 && !row.linked)
						updateLinkProofsOfPrivateChain(arrPrivateElements, row.unit, row.message_index, row.output_index, cb, validateAndSave);
					else
						validateAndSave();
					
				},
				function(){
					unlock();
					var arrNewUnits = Object.keys(assocNewUnits);
					if (arrNewUnits.length > 0)
						eventBus.emit("new_my_transactions", arrNewUnits);
				}
			);
		});
	});
}
```

**File:** network.js (L2565-2592)
```javascript
// light only
function requestUnfinishedPastUnitsOfPrivateChains(arrChains, onDone){
	mutex.lock(["private_chains"], function(unlock){
		function finish(){
			unlock();
			if (onDone)
				onDone();
		}
		privatePayment.findUnfinishedPastUnitsOfPrivateChains(arrChains, true, function(arrUnits){
			if (arrUnits.length === 0)
				return finish();
			breadcrumbs.add(arrUnits.length+" unfinished past units of private chains");
			requestHistoryFor(arrUnits, [], err => {
				if (err) {
					console.log(`error getting history for unfinished units of private payments`, err);
					return finish();
				}
				// get units that are still new or unstable after refreshing the history
				storage.filterNewOrUnstableUnits(arrUnits, async arrMissingUnits => {
					if (arrMissingUnits.length === 0) return finish();
					console.log(`will delete unhandled private payments whose units are not known after 1 day`, arrMissingUnits);
					await db.query(`DELETE FROM unhandled_private_payments WHERE unit IN(${arrMissingUnits.map(db.escape).join(', ')}) AND creation_date < ${db.addTime('-1 DAY')}`);
					finish();
				});
			});
		});
	});
}
```
