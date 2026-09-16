### Title
Duplicate-output shortcut in `validateAndSavePrivatePaymentChain` lets a private-payment counterparty get an unverified private-payment chain marked "valid" and forwarded to other wallet holders - (File: `private_payment.js`)

### Summary
`private_payment.js`'s `validateAndSavePrivatePaymentChain` contains a "duplicate" fast-path that, on a superficial match of a *single* revealed output's fields, skips the entire cryptographic chain-validation routine (`indivisible_asset.js`/`divisible_asset.js` `validateAndSavePrivatePaymentChain` → `validatePrivatePayment`/`parsePrivatePaymentChain`, which check spend proofs, output hashes, chain linkage and double-spends) and immediately calls `ifOk()`. This is architecturally the same bug class as the reported repomix issue: an alternate, lightly-checked path (fast dedup check) bypasses the "real" validation used everywhere else, and the result is then trusted and propagated to other consumers (forwarded to other wallet devices / used to fire "payment received" events).

### Finding Description
`validateAndSavePrivatePaymentChain` in [1](#0-0)  receives `arrPrivateElements`, an attacker-influenced array (it is delivered over the wire via `handleOnlinePrivatePayment`/`handlePrivatePaymentChains`, i.e. reachable from any private-payment counterparty or a forwarding device).

Before running the real, protocol-mandated validation (`assetModule.validateAndSavePrivatePaymentChain`, which internally calls `parsePrivatePaymentChain`/`validatePrivatePayment` to check spend proofs, `output_hash` integrity, chain linkage between elements, and double-spend state — see [2](#0-1)  and [3](#0-2) ), the code performs a cheap "duplicate" check: [4](#0-3) 

The check only reads a single already-stored row (`address, denomination, amount, blinding`) for the *head* element's `(unit, message_index[, output_index])`, and if `bDuplicate` is true it returns `transaction_callbacks.ifOk()` **without ever calling `assetModule.validateAndSavePrivatePaymentChain`**. Critically:

1. For divisible assets the match is done with `.some()` over `payload.outputs`, i.e. matching **any one** output field-set against the stored row is enough — the check does not require that *all* outputs, nor the `inputs` array, nor the rest of the chain (`arrPrivateElements[1..]`, which can be arbitrarily long and contain any fabricated spend history) match anything real.
2. None of the fields that make the real validator secure — spend-proof hashes, `output_hash` recomputation, chain-of-custody continuity (`prevElement.unit`/`message_index`/`output_index` matching), or double-spend detection — are checked in this fast path.
3. Because the row match only requires knowledge of `(address, denomination, amount, blinding)` for one output, and blinding factors are shared with everyone who received or co-signed that private element (recipient and cosigner chains, see `arrRecipientChains`/`arrCosignerChains` in [5](#0-4) ), any private-payment counterparty who legitimately received one output of a chain can reuse that fragment to make an entirely different, unvalidated `arrPrivateElements` chain "pass" as `ifOk()`.

This `ifOk()` result is trusted by callers exactly as if full validation had succeeded: in `wallet.js`'s `handlePrivatePaymentChains`, once `assocValidatedByKey[key]` becomes true for a chain, the code fires `emitNewPrivatePaymentReceived`, treats the payment as accepted, and forwards the *entire, unvalidated* `arrChains` (including the bogus/fabricated tail elements and unmatched extra outputs) on to other members via `forwardPrivateChainsToOtherMembersOfSharedAddresses`/`forwardPrivateChainsToOtherMembersOfOutputAddresses` ( [6](#0-5) ), and via `network.js`'s `handleOnlinePrivatePayment` down through `handleSavedPrivatePayments` ( [7](#0-6) ), the fabricated data is passed along as "accepted" data to other devices/peers.

### Impact Explanation
Because the "duplicate" fast path bypasses spend-proof verification, output-hash verification and chain-linkage checks for everything except one already-known output field-set, a private-payment counterparty can craft a chain that:
- reuses a previously legitimate/known output's `(address, denomination, amount, blinding)` to satisfy the shortcut, while
- attaching arbitrary/forged predecessor elements or additional outputs that were never actually verified against real spend proofs or issuance data.

The result is accepted (`ifOk`) and forwarded to other cosigners/devices as a validated private-payment chain, without the DAG-level guarantees (no double-spend, no forged issuance, correct chain of custody) that `assetModule.validateAndSavePrivatePaymentChain` normally enforces. This creates a node-disagreement-on-validity condition: the accepting node reports "accepted"/emits `new_my_transactions` and forwards a chain that was never actually checked for correctness, while any node that independently re-validates it (because it lacks the matching duplicate row) will reject it — a direct violation of consistent validity determination for private, off-chain-verified asset transfers, and a vector for tricking wallet UI/state into believing an unverified private payment is good.

### Likelihood Explanation
Reachable by an unprivileged actor who is a legitimate private-payment counterparty or cosigner (someone who has already received/seen one leaf output of a chain, which the protocol shares with recipients and cosigners by design). No special privileges beyond normal wallet participation are required; the crafted chain is delivered through the standard `private_payment`/`private_payment_chains` wallet message handling path (`network.js:handleOnlinePrivatePayment`, `wallet.js:handlePrivatePaymentChains`), both of which are exposed to correspondent devices.

### Recommendation
- Remove or drastically restrict the duplicate-detection shortcut in `private_payment.js`; it should, at minimum, still verify the entire submitted chain (all outputs, all inputs, full chain-of-custody) against `assetModule.validateAndSavePrivatePaymentChain`'s checks even if the head output happens to match a stored row.
- If the intent is purely to avoid redundant DB writes for an already-processed unit/message/output, perform the duplicate check only after confirming that the *entire* incoming chain byte-for-byte (or hash-for-hash) matches a chain that was previously fully validated and stored, not just one output's plaintext fields.
- Ensure the fast path cannot cause `ifOk()`/acceptance events and forwarding to other devices unless the full chain has actually passed real validation at least once (by this node or a trusted party with proof).

### Proof of Concept
Conceptual PoC (protocol-level, requires knowledge of one leaf output's plaintext fields, obtainable by any legitimate recipient/cosigner of that output):
1. Attacker is a legitimate recipient of one output O of a private (indivisible or divisible) asset chain; O has already been fully validated and stored by the target node with `address`, `denomination`, `amount`, `blinding` known to attacker (shared as part of normal delivery to recipient/cosigner, see `arrRecipientChains`/`arrCosignerChains`).
2. Attacker builds a new `arrPrivateElements` array whose head element's payload contains an output entry that reproduces O's `denomination`/`amount`/`address`/`blinding` exactly (satisfying `bDuplicate`), but whose `payload.inputs` and/or additional `payload.outputs`, and/or predecessor elements (`arrPrivateElements[1..]`) are arbitrary/forged (e.g., referencing a nonexistent or already-spent source, or extra outputs to attacker-controlled addresses).
3. Attacker sends this chain to the target node via the standard `private_payment_chains`/`private_payment` message (`handlePrivatePaymentChains` in `wallet.js`, or `handleOnlinePrivatePayment` in `network.js`).
4. `private_payment.js:validateAndSavePrivatePaymentChain` finds the stored row for `(unit, asset, message_index[, output_index])` matches on the head output and returns `ifOk()` without ever calling `indivisible_asset.js`/`divisible_asset.js`'s `validateAndSavePrivatePaymentChain`, i.e., without verifying spend proofs, output hashes, or chain linkage for the forged parts of the chain.
5. The target node treats the whole crafted chain as validated: it fires acceptance events and, per `wallet.js:handlePrivatePaymentChains`, forwards the entire unvalidated `arrChains` to other cosigners/output-address holders as though it were a proven, correct private payment.

Note: I was unable to execute this scenario against a live node (no code-execution access here); the PoC is derived from static analysis of the cited functions and their call graph. A background Devin session with runtime access would be needed to fully instrument and confirm the exact downstream effects (e.g., precisely which UI/state changes occur on the receiving side) if further confirmation is required.

### Citations

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

**File:** private_payment.js (L61-107)
```javascript
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
```

**File:** indivisible_asset.js (L20-181)
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

**File:** indivisible_asset.js (L863-900)
```javascript
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

**File:** wallet.js (L998-1076)
```javascript
	var checkIfAllValidated = function(){
		if (!assocValidatedByKey) // duplicate call - ignore
			return console.log('duplicate call of checkIfAllValidated');
		for (var key in assocValidatedByKey)
			if (!assocValidatedByKey[key])
				return console.log('not all private payments validated yet');
		eventBus.emit('all_private_payments_handled', from_address);
		eventBus.emit('all_private_payments_handled-' + arrChains[0][0].unit);
		assocValidatedByKey = null; // to avoid duplicate calls
		if (!body.forwarded){
			if (from_address) emitNewPrivatePaymentReceived(from_address, arrChains, current_message_counter);
			// note, this forwarding won't work if the user closes the wallet before validation of the private chains
			var arrUnits = arrChains.map(function(arrPrivateElements){ return arrPrivateElements[0].unit; });
			db.query("SELECT address FROM unit_authors WHERE unit IN(?)", [arrUnits], function(rows){
				var arrAuthorAddresses = rows.map(function(row){ return row.address; });
				// if the addresses are not shared, it doesn't forward anything
				forwardPrivateChainsToOtherMembersOfSharedAddresses(arrChains, arrAuthorAddresses, from_address, true);
			});
		}
		profiler.print();
	};
	
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
		function(err){
			bParsingComplete = true;
			if (err){
				cancelAllKeys();
				return callbacks.ifError(err);
			}
			checkIfAllValidated();
			handledChainsCache[cache_key] = Date.now();
			callbacks.ifOk();
			// forward the chains to other members of output addresses
			if (!body.forwarded)
				forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, true);
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
