### Title
Users who repeatedly re-transfer an indivisible private asset unbounded-grow their private payment chain, causing self-DOS on future validation - ([File: indivisible_asset.js])

### Summary
Divisible private assets are only ever validated as a single element (`divisible_asset.js` `validateAndSavePrivatePaymentChain` handles `arrPrivateElements[0]` only), but indivisible (fixed-denomination) private assets track full provenance as a linked chain of private elements from issuance to the current holder. Every time a coin changes hands, `buildPrivateElementsChain` walks the entire ancestry back to the issuance and `parsePrivatePaymentChain`/`validateAndSavePrivatePaymentChain` re-validates every single hop of that chain, with no upper bound on chain length. An address that repeatedly receives and re-sends (or "bounces") the same private coin will grow the chain length without limit, making every future validation of that coin increasingly expensive, eventually self-DOSing the holder's ability to receive/spend/forward that private coin.

### Finding Description
`buildPrivateElementsChain` in [1](#0-0)  recursively walks up from the current output to the issuing input (`readPayloadAndGoUp`), pushing one `objPrivateElement` per hop with no depth/length cap.

When a private (indivisible) payment is received, `validateAndSavePrivatePaymentChain` → `parsePrivatePaymentChain` iterates the *entire* chain (`arrPrivateElements`, ordered from current unit back to issuance) with `async.forEachOfSeries`, calling `validatePrivatePayment` (which itself issues multiple DB queries: spend-proof lookup, graph inclusion check, full payment validation) for every element in the chain: [2](#0-1) [3](#0-2) 

This same, unbounded, full-chain re-validation occurs any time the chain is (re)processed: when the sender composes a payment and validates+saves the recipient/cosigner chains (`getSavingCallbacks` → `buildPrivateElementsChain` → `validateAndSavePrivatePaymentChain`, [4](#0-3) ), when a light client restores chains (`restorePrivateChains`, [5](#0-4) ), and when a peer/hub delivers a private payment over the network (`handleOnlinePrivatePayment` → `privatePayment.validateAndSavePrivatePaymentChain`, [6](#0-5) ).

`private_payment.js`'s top-level `validateAndSavePrivatePaymentChain` performs no length/size validation on `arrPrivateElements` before dispatching to the asset-specific handler: [7](#0-6) 

Unlike other DoS-classes in ocore that are explicitly bounded (address-definition depth `MAX_DEPTH=100` in `aa_validation.js`, formula recursion depth cap of 100 in `formula/validation.js`, `MAX_COMPLEXITY`/`MAX_OPS` limits in `definition.js`, array/dictionary literal caps of 100 elements and `isTooBigObj` limits in `formula/evaluation.js`), the private-payment chain has **no analogous cap**. Any address holder can grow the chain simply by legitimately sending and receiving the same private coin repeatedly (e.g., an actively-used private-asset wallet, or a coin deliberately "washed" back and forth by its own owner), each hop appending one element that must be revalidated on every subsequent transfer, forever, by every recipient (including the original holder if the coin returns).

### Impact Explanation
This is a self-inflicted, growing-cost DOS analogous to the reference report: the *victim* is whoever ends up holding (or is asked to accept) the coin with the bloated chain. As chain length grows, `parsePrivatePaymentChain`'s serial per-element DB queries and `validatePrivatePayment`'s nested queries (spend-proof lookup + `graph.determineIfIncluded` + full `validation.validatePayment`) make chain revalidation increasingly slow, eventually becoming impractical to complete (analogous to the OOG condition in the reference report), which effectively freezes the ability to further transfer/accept that specific private coin — a loss/freezing of the user's own funds in that indivisible private asset, and can be weaponized exactly as described in the reference (creating a coin that looks spendable/valuable but is a "honey pot": the last owner cannot practically forward it further, or a buyer who acquires it cannot spend it onward without paying an ever-increasing validation cost). Full nodes and light wallets validating the chain both incur this cost.

### Likelihood Explanation
Likelihood is Medium: any address holder can trigger this purely through normal usage (repeatedly sending/spending an indivisible private coin among their own addresses or in a loop with a counterparty), with no special privileges, and no validation-time or chain-length guard exists anywhere in `indivisible_asset.js` or `private_payment.js` to prevent it. It requires an active, patient user (or malicious crafting) over many transactions to reach a chain length that is practically un-validatable, similar to the CVG lock-extension scenario in the reference report (many small, cheap, legitimate operations accumulate into an unbounded structure that is later fully iterated).

### Recommendation
Add an explicit maximum chain length (analogous to `MAX_DEPTH`/`MAX_COMPLEXITY`/`MAX_OPS` elsewhere in ocore) checked in `buildPrivateElementsChain` (abort/limit while walking up) and/or in `parsePrivatePaymentChain`/`validateAndSavePrivatePaymentChain` and in the top-level `private_payment.js` `validateAndSavePrivatePaymentChain` before iterating `arrPrivateElements`, rejecting chains beyond a safe bound. Consider also allowing/encouraging periodic "chain compaction" (e.g., re-issuing or checkpointing ownership) so legitimate frequent transfers of the same indivisible private coin do not permanently inflate validation cost for all future holders.

### Proof of Concept
Not independently reproduced in a live network; based on static code-path tracing:
1. Address A receives an indivisible private coin (chain length 1, issuance element only).
2. A repeatedly sends the coin to B, and B sends it back to A (or A sends to many changed addresses/self), N times. Each transfer step appends one element via `buildPrivateElementsChain`'s `readPayloadAndGoUp` recursion ( [8](#0-7) ), with no cap on N.
3. On the N+1-th transfer, whoever validates the chain (recipient's node, or the sender's own node through `getSavingCallbacks`'s `preCommitCallback`) must run `parsePrivatePaymentChain` over all N elements serially ( [9](#0-8) ), each doing multiple DB round trips via `validatePrivatePayment` ( [10](#0-9) ).
4. As N grows without bound, this validation step's cost grows linearly and unboundedly, eventually making it impractical to complete — mirroring the reference report's "OOG on claim" but manifesting as an unbounded/expensive private-chain validation instead.

### Citations

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

**File:** indivisible_asset.js (L239-297)
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

**File:** indivisible_asset.js (L869-901)
```javascript
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
								},
```

**File:** indivisible_asset.js (L984-1063)
```javascript
function restorePrivateChains(asset, unit, to_address, handleChains){
	var arrRecipientChains = [];
	var arrCosignerChains = [];
	db.query(
		"SELECT DISTINCT message_index, denomination, payload_hash, version \n\
		FROM outputs JOIN messages USING(unit, message_index) CROSS JOIN units USING(unit) WHERE unit=? AND asset=?", 
		[unit, asset], 
		function(rows){
			async.eachSeries(
				rows,
				function(row, cb){
					var payload = {asset: asset, denomination: row.denomination};
					var message_index = row.message_index;
					db.query(
						"SELECT src_unit, src_message_index, src_output_index, denomination, asset FROM inputs WHERE unit=? AND message_index=?", 
						[unit, message_index],
						function(input_rows){
							if (input_rows.length !== 1)
								throw Error("not 1 input");
							var input_row = input_rows[0];
							if (input_row.asset !== asset)
								throw Error("assets don't match");
							if (input_row.denomination !== row.denomination)
								throw Error("denominations don't match");
							if (input_row.src_message_index === null || input_row.src_output_index === null)
								throw Error("only transfers supported");
							var input = {
								unit: input_row.src_unit,
								message_index: input_row.src_message_index,
								output_index: input_row.src_output_index
							};
							payload.inputs = [input];
							db.query(
								"SELECT address, amount, blinding, output_hash FROM outputs \n\
								WHERE unit=? AND asset=? AND message_index=? ORDER BY output_index", 
								[unit, asset, message_index],
								function(outputs){
									if (outputs.length === 0)
										throw Error("outputs not found for mi "+message_index);
									if (!outputs.some(function(output){ return (output.address && output.blinding); }))
										throw Error("all outputs are hidden");
									payload.outputs = outputs;
									var hidden_payload = _.cloneDeep(payload);
									hidden_payload.outputs.forEach(function(o){
										delete o.address;
										delete o.blinding;
									});
									var payload_hash = objectHash.getBase64Hash(hidden_payload, row.version !== constants.versionWithoutTimestamp);
									if (payload_hash !== row.payload_hash)
										throw Error("wrong payload hash");
									async.forEachOfSeries(
										payload.outputs,
										function(output, output_index, cb3){
											if (!output.address || !output.blinding) // skip
												return cb3();
											// we have only heads of the chains so far. Now add the tails.
											buildPrivateElementsChain(
												db, unit, message_index, output_index, payload, 
												function(arrPrivateElements){
													if (output.address === to_address)
														arrRecipientChains.push(arrPrivateElements);
													arrCosignerChains.push(arrPrivateElements);
													cb3();
												}
											);
										},
										cb
									);
								}
							);
						}
					);
				},
				function(){
					handleChains(arrRecipientChains, arrCosignerChains);
				}
			);
		}
	);
}
```

**File:** network.js (L2375-2429)
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
