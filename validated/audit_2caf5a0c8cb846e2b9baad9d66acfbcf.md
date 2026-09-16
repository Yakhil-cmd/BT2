Confirmed: for indivisible (fixed-denomination) private assets, `parsePrivatePaymentChain` in `indivisible_asset.js` validates the **entire** chain of private elements from the current owner back to the original issuance, one element at a time, on every single transfer — there is no depth cap in `validateAndSavePrivatePaymentChain`/`parsePrivatePaymentChain`/`buildPrivateElementsChain`. Each hop appends another element that must be re-verified by every subsequent recipient, so the cost of accepting a private payment grows linearly (and unboundedly) with the number of times that specific coin has been re-transferred — directly analogous to the reported `_claimCvgSdtRewards` bug, where cost grows unboundedly with elapsed unclaimed cycles and eventually makes the operation infeasible/unprocessable, causing fund loss/freezing for the (unprivileged) counterparty who ends up holding the coin.

### Title
Unbounded growth of indivisible private-asset payment chains causes DoS/fund-freezing on receipt - (File: indivisible_asset.js)

### Summary
`indivisible_asset.js` builds and validates indivisible (fixed-denomination) private payment chains by walking, element by element, from the currently received output all the way back to the original `issue` input, with no limit on chain length. A private-payment counterparty (or a colluding chain of counterparties, including the payer/recipient of a legitimate transfer, or an attacker deliberately hoping around addresses they control) can grow this chain indefinitely before finally sending the coin to a victim. The victim's node/wallet must then synchronously walk and validate the full, ever-growing chain to accept the payment.

### Finding Description
`buildPrivateElementsChain` in [1](#0-0)  recursively calls `readPayloadAndGoUp` for every prior hop of a coin, from the current output all the way back to the `issue` input, appending each ancestor element to `arrPrivateElements` with no depth limit.

On the receiving/validating side, `parsePrivatePaymentChain` in [2](#0-1)  iterates the **entire** received chain with `async.forEachOfSeries`, calling `validatePrivatePayment` (spend-proof check, source-output inclusion check via `graph.determineIfIncluded`, and full `validation.validatePayment`) for every element in the chain: [3](#0-2) 

`validateAndSavePrivatePaymentChain` then performs additional per-element SQL writes for every hop: [4](#0-3) 

This is reached whenever any counterparty sends a private (indivisible) asset payment: `private_payment.js`'s `validateAndSavePrivatePaymentChain` dispatches straight to `indivisible_asset.validateAndSavePrivatePaymentChain` for fixed-denomination assets [5](#0-4) , and this in turn is invoked directly from network message handling of a peer- or hub-forwarded private payment in `network.js`'s `handleOnlinePrivatePayment`/`handleSavedPrivatePayments` [6](#0-5)  and from `wallet.js`'s `handlePrivatePaymentChains`, both of which are reachable from an unprivileged private-payment counterparty (a device peer sending a payment message) [7](#0-6) . There is no cap on `arrPrivateElements.length` anywhere along this path — I searched `constants.js` and validation code for a max-chain-length constant and found none.

Nothing prevents a party who repeatedly re-spends the same private coin between addresses they control from inflating this chain to an arbitrary length before finally paying it to a victim. Since every future holder must revalidate the full chain from genesis on every subsequent transfer (chain length only grows, it is never compacted/pruned), the validation cost (recursive DB round trips, `graph.determineIfIncluded` graph walks, and full payment validation per hop) grows without bound over the life of the coin.

### Impact Explanation
Once the chain becomes sufficiently long, a recipient's wallet/node incurs prohibitively expensive, purely sequential (`async.forEachOfSeries`/recursive `readPayloadAndGoUp`) validation work to accept a single payment. This can:
- Make the coin practically unspendable/unreceivable for its holder (funds effectively frozen — the same "unclaimable funds" outcome as the reference report), since every future transfer inherits and must re-validate the same ever-growing prefix.
- Provide a griefing vector: any party in the private chain (a "private-payment counterparty") can pad the chain with many cheap self-transfers to weaponize this against a future recipient, at asymmetric cost (cheap to create hops, expensive to validate them all cumulatively for every subsequent holder).

This matches the allowed "concrete... AA fund loss or freezing" / private payment chain criteria in scope.

### Likelihood Explanation
Likelihood is moderate-to-high: creating additional private-payment hops requires no special privilege — any owner of a private, fixed-denomination-asset coin can simply keep transferring it to addresses they control before finally paying a counterparty, and each hop is a normal, valid private payment. No consensus-level cap exists to stop this. The main constraint is that the attacker must be willing to pay their own transaction fees to build the chain, which is a low economic barrier for meaningfully harming a specific target.

### Recommendation
Introduce and enforce a maximum private-payment chain length (or a periodic "chain compaction" / re-issuance mechanism) that is checked during validation (e.g., in `parsePrivatePaymentChain`/`validatePrivatePaymentChain` and enforced consensus-wide via `validation.js`), rejecting or requiring re-issuance of coins whose chain exceeds the limit, and/or provide a way to "flatten" a long private chain into a shorter proof so that revalidation cost does not grow unboundedly with the coin's transfer history.

### Proof of Concept
1. Issue an indivisible private asset coin (fixed denomination) to address A1, controlled by the attacker.
2. Repeatedly transfer the coin between addresses A1→A2→A3→...→An, all controlled by the attacker, for a large N (each transfer is a normal, independently valid private payment, so none of it is rejected by existing validation).
3. Finally, send the coin from An to the victim V as a legitimate-looking payment.
4. When V (or V's wallet/hub) receives the private payment, `buildPrivateElementsChain`/`parsePrivatePaymentChain` must walk and fully re-validate all N private elements back to the original issuance [1](#0-0) [2](#0-1) , causing validation time/DB load to grow linearly with N with no cap, degrading or effectively blocking V's ability to accept/spend the coin as N grows large.

### Citations

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

**File:** indivisible_asset.js (L619-720)
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
```

**File:** private_payment.js (L104-105)
```javascript
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
```

**File:** network.js (L2412-2440)
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
```

**File:** wallet.js (L1020-1064)
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
		},
```
