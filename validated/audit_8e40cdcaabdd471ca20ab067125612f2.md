### Title
Unbounded private payment chain length causes unbounded validation cost for indivisible (fixed-denomination) private assets - (File: `indivisible_asset.js`)

### Summary
For indivisible ("blackbyte"-style) private assets, every re-transfer of a coin must carry and re-validate the *entire* private payment chain back to the original issuance. Neither the chain-building code nor the chain-validation code enforces any maximum length on this chain, so a malicious counterparty can force the chain to grow arbitrarily long by repeatedly re-transferring the same private coin to themselves (or colluding addresses) before finally sending it to a victim. The victim's node/wallet must then walk and validate the full, ever-growing chain in `parsePrivatePaymentChain`, causing validation cost (and memory/JSON payload size) to grow linearly and unboundedly with the number of prior transfers, with no way to partially validate or reject an oversized chain.

### Finding Description
When a private, fixed-denomination asset payment is sent, the recipient reconstructs the whole ownership history of the coin via `buildPrivateElementsChain()`, which recursively walks backward through inputs with `readPayloadAndGoUp()` until it reaches the original `issue` element, with no bound on recursion depth or on `arrPrivateElements.length`: [1](#0-0) 

The resulting chain, however long, is then validated element-by-element on receipt in `parsePrivatePaymentChain()`, iterating with `async.forEachOfSeries` over the entire array and running `validatePrivatePayment()` (spend-proof check + `graph.determineIfIncluded` + full payment validation) for every element — again with no cap on `arrPrivateElements.length`: [2](#0-1) 

`validateAndSavePrivatePaymentChain()` then iterates the same full-length array again to persist all inputs/outputs: [3](#0-2) 

On the network/wallet side, incoming chains are accepted and stored/forwarded without any length limit check on `arrChains`/`arrPrivateElements`: the code validates element *shape* but never the chain length before queueing (`unhandled_private_payments`, JSON-serialized) or forwarding: [4](#0-3) [5](#0-4) 

Because nothing prevents an attacker from privately re-transferring the same coin to themselves thousands of times before finally paying the victim, the victim (or hub relaying on their behalf) is forced to reconstruct/validate/store this whole chain — an amount of work fully controlled by the attacker and unbounded in size, directly mirroring the original report's pattern of "unbounded loop over user-controlled history with no way to process it incrementally or reject it."

### Impact Explanation
A malicious counterparty in a private (fixed-denomination) asset payment can craft/force an arbitrarily long private-payment chain. The recipient's node has no defense: it cannot reject the payment for being "too long," and validating it consumes unbounded CPU, DB queries, and memory (the whole chain is buffered in-memory and stringified into `unhandled_private_payments.json`). This can make the recipient wallet/hub unable to validate and thus unable to ever accept the (legitimate) private funds sent to it — effectively freezing those funds for the recipient, and/or degrading a hub/light-vendor that must process such chains on behalf of light clients. This matches the "freezing of funds" / inability to confirm a valid unit class of impact.

### Likelihood Explanation
Any user who can issue and repeatedly re-transfer a private, fixed-denomination asset controls the length of the chain they later hand to a victim; no permission beyond being a private-payment counterparty/asset issuer is required. Building a long chain merely requires posting many ordinary private-payment units to oneself before finally forwarding the coin, which is cheap for the attacker (normal transaction fees) but imposes disproportionate, unbounded validation cost on the victim.

### Recommendation
Enforce a hard maximum private-payment chain length (e.g., a `MAX_PRIVATE_CHAIN_LENGTH` constant) both when building the chain (`buildPrivateElementsChain`) and, more importantly, when receiving/validating one (`parsePrivatePaymentChain`, `handleOnlinePrivatePayment`, `handlePrivatePaymentChains`), rejecting/erroring out chains that exceed the limit before doing any expensive per-element validation or DB writes. Consider also periodically "compacting" long-lived indivisible-asset chains (e.g., via a checkpoint/re-issue mechanism) so ordinary use doesn't hit the limit while pathological chains built purely to grief a recipient are rejected early.

### Proof of Concept
1. Issue a private, fixed-denomination asset coin (`input.type === 'issue'`) to address A.
2. Have A repeatedly send the same coin privately to itself (or a colluding address) N times (e.g., N = 50,000), each time producing a new `objPrivateElement` referencing the previous one, per the chain structure validated in `parsePrivatePaymentChain` (`indivisible_asset.js:186-236`).
3. Finally, send the coin privately to victim V.
4. V's wallet (or the hub relaying on V's behalf via `handlePrivatePaymentChains` in `wallet.js:955`) receives an `arrPrivateElements` array of length N+1 with no length check, and must run `validatePrivatePayment` N+1 times sequentially (`indivisible_asset.js:198-235`), each involving spend-proof lookups and `graph.determineIfIncluded` — a cost fully controlled by the attacker and scalable without bound, while V has no way to reject the oversized chain or claim/validate the payment incrementally.

### Citations

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

**File:** indivisible_asset.js (L619-641)
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
```

**File:** wallet.js (L955-984)
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
	}
	profiler.increment();
```

**File:** network.js (L2375-2411)
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

```
