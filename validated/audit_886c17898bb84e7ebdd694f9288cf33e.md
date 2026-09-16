### Title
Unbounded private payment chain length causes DoS when validating indivisible (fixed-denomination) private asset transfers - (File: `indivisible_asset.js`)

### Summary
`parsePrivatePaymentChain`/`buildPrivateElementsChain` in `indivisible_asset.js` process an `arrPrivateElements` array whose length is fully controlled by whoever constructs the private payment chain (the private-payment counterparty). No file in the codebase caps this chain length. A malicious counterparty can craft (or, since they issue/transfer among their own addresses, cheaply extend) a chain with an extremely large number of hops and send it in a single `private_payment` device message. The receiving wallet/node must synchronously walk the *entire* chain inside one open DB transaction before it can accept or reject it, exactly mirroring the "unbounded array grown by an untrusted party, iterated in full on every relevant operation" pattern from the referenced `_removeNft` finding.

### Finding Description
When a fixed-denomination ("indivisible"/blackbyte) private asset is transferred, the sender builds the full history of the coin with `buildPrivateElementsChain`, which recursively walks `input.unit → src_unit` all the way back to the issuance, pushing every hop into `arrPrivateElements` with no length limit: [1](#0-0) [2](#0-1) 

The whole chain is delivered as one device message and handled by `handleOnlinePrivatePayment`/`handlePrivatePaymentChains`, which only validate structural shape of the array elements, never its length: [3](#0-2) [4](#0-3) 

Validation then calls `private_payment.js`'s `validateAndSavePrivatePaymentChain`, which opens a DB transaction (`BEGIN` … `COMMIT`) and dispatches to `indivisibleAsset.validateAndSavePrivatePaymentChain`: [5](#0-4) [6](#0-5) 

`parsePrivatePaymentChain` then iterates the **entire** `arrPrivateElements` array with `async.forEachOfSeries`, running `validatePrivatePayment` for each hop (which itself issues multiple sequential DB queries: read spend proof, `graph.determineIfIncluded`, and `validation.validatePayment`): [7](#0-6) 

and afterwards `validateAndSavePrivatePaymentChain` writes one `INSERT`/`UPDATE` query pair per hop, all inside the single open transaction: [8](#0-7) 

No function in this call path (`handleOnlinePrivatePayment`, `handlePrivatePaymentChains`, `validateAndSavePrivatePaymentChain`, `parsePrivatePaymentChain`, `buildPrivateElementsChain`) enforces any `MAX_CHAIN_LENGTH`-style bound on `arrPrivateElements.length`, unlike other attacker-facing arrays in the codebase which are explicitly capped (e.g. `MAX_INPUTS_PER_PAYMENT_MESSAGE`, `MAX_OUTPUTS_PER_PAYMENT_MESSAGE`, `MAX_ATTESTORS_PER_ASSET`, `MAX_MESSAGES_PER_UNIT`). This is the exact bug class from the reference report: an externally-reachable, attacker-grown array with an unbounded iteration cost on every future processing pass, with no way for the victim to bound or reject the work cheaply before doing it.

### Impact Explanation
Because the whole chain is validated and written inside a single open SQL transaction (`BEGIN` at `private_payment.js:46`, `COMMIT` only after the full `arrQueries` batch completes in `indivisible_asset.js:291`), an attacker-supplied chain with a very large number of hops forces the receiving node to hold that transaction open for a long time while performing many sequential DB round-trips (at least 3 queries per hop for validation, plus 2+ write queries per hop for saving). On SQLite-backed nodes (the common deployment for wallets/hubs), an open write transaction blocks all other writers to the database, so while this oversized private-payment chain is being processed, the victim node cannot write new units — i.e., it cannot confirm/save any other incoming unit — for the duration of the attack. This matches "network unable to confirm new units" for the affected node, and since this can be delivered directly by any private-payment counterparty (a normally-untrusted party from the victim's perspective), it is a legitimate DoS/griefing vector, not merely a resource-tuning inconvenience.

### Likelihood Explanation
Any user who accepts a private (indivisible) asset payment from an unknown or adversarial counterparty is exposed: the attacker only needs to issue the asset to themselves and privately transfer it among addresses they control an arbitrary number of times before finally sending it to the victim, then deliver the full accumulated chain via the normal `private_payment` device-message flow. No special permissions or network position are required — this is reachable from a single private-payment counterparty exactly as scoped.

### Recommendation
Impose an explicit maximum chain length (e.g. a `MAX_PRIVATE_CHAIN_LENGTH` constant) checked as early as possible — in `wallet.js`'s `handlePrivatePaymentChains`, `network.js`'s `handleOnlinePrivatePayment`, and `private_payment.js`'s `validateAndSavePrivatePaymentChain` — before opening any DB transaction, rejecting/bouncing chains that exceed it. Additionally, avoid holding a single long-lived transaction across the whole chain; consider batching/limiting DB round trips per hop or validating length/size before starting the transaction.

### Proof of Concept
1. Attacker issues an indivisible (fixed-denomination) private asset to address A1 (`type: 'issue'`).
2. Attacker privately transfers the coin from A1→A2→A3→…→AN, where N is very large (e.g. tens of thousands of hops), using addresses they control; each hop is a cheap minimal-size private payment unit.
3. Attacker sends the coin from AN to the victim, and the wallet builds the head chain via `buildPrivateElementsChain` (`indivisible_asset.js:619`), which will contain N private elements.
4. Attacker (or the victim's own wallet code, unknowingly on victim's behalf, since the sender supplies the full chain in the `private_payment` device message) delivers the entire `arrPrivateElements`/`arrChains` array to the victim via `wallet.js:handlePrivatePaymentChains` → `network.js:handleOnlinePrivatePayment`.
5. The victim's node calls `private_payment.js:validateAndSavePrivatePaymentChain`, opens a transaction, and `indivisible_asset.js:parsePrivatePaymentChain` walks all N elements sequentially with multiple DB queries each, keeping the DB transaction open for the entire time — stalling the victim's ability to write/confirm any other unit meanwhile.

### Citations

**File:** indivisible_asset.js (L187-235)
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

**File:** indivisible_asset.js (L619-638)
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
```

**File:** indivisible_asset.js (L707-715)
```javascript
						arrPrivateElements.push(objPrivateElement);
						(input.type === 'issue') 
							? handlePrivateElements(arrPrivateElements)
							: readPayloadAndGoUp(input.unit, input.message_index, input.output_index);
					}
				);
			}
		);
	}
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

**File:** network.js (L2376-2378)
```javascript
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
```

**File:** private_payment.js (L45-60)
```javascript
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
```

**File:** private_payment.js (L104-105)
```javascript
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
```
