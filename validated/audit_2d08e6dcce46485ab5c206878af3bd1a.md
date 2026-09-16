### Title
Unbounded private-payment chain arrays allow memory-exhaustion DoS via `handlePrivatePaymentChains` - ([File: wallet.js])

### Summary
`handlePrivatePaymentChains()` in `wallet.js` (invoked by a paired device sending a `private_payments` message over the hub) and the downstream `network.handleOnlinePrivatePayment()` / `private_payment.js` / `divisible_asset.js` / `indivisible_asset.js` validators accept attacker-supplied arrays (`body.chains`, each chain's `payload.inputs`/`payload.outputs`) with only a generic non-empty/object-shape check via `Array.prototype.every`, but never enforce the same anti-spam caps (`constants.MAX_INPUTS_PER_PAYMENT_MESSAGE`, `constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE`, `MAX_MESSAGES_PER_UNIT`) that are applied to regular on-chain units in `validation.js`. This mirrors the Cosign bug class: memory/CPU proportional to an attacker-controlled count is allocated/processed before any size bound is checked.

### Finding Description
For normal DAG units, `validation.js` enforces strict anti-spam caps before doing expensive work: [1](#0-0) [2](#0-1) 

However, the private-payment path reachable directly from a paired device (a party explicitly listed as in-scope: "paired device") bypasses these caps. `handlePrivatePaymentChains` only checks that the structure looks well-formed, not that it is bounded in size: [3](#0-2) 

It then iterates `arrChains` (unbounded length) and calls `network.handleOnlinePrivatePayment` for each, which persists the entire attacker-controlled JSON blob to the DB and/or forwards it into validation: [4](#0-3) [5](#0-4) 

Downstream, `divisible_asset.js`'s `validateAndSavePrivatePaymentChain` / `validateDivisiblePrivatePayment` iterates `payload.inputs` and `payload.outputs` with plain `for` loops and `async.eachSeries`, allocating a DB query and an in-memory `arrSpendProofs`/`arrQueries` entry per element, with no upper bound check on `payload.inputs.length` or `payload.outputs.length`: [6](#0-5) [7](#0-6) [8](#0-7) 

The equivalent indivisible-asset private chain path also loops over `arrPrivateElements` (also unbounded, from `arrChains` outer array) without any cap: [9](#0-8) [10](#0-9) 

Unlike public units, whose total serialized size and message/array counts are bounded by `constants.MAX_UNIT_LENGTH`, `MAX_MESSAGES_PER_UNIT`, `MAX_INPUTS_PER_PAYMENT_MESSAGE`, and `MAX_OUTPUTS_PER_PAYMENT_MESSAGE` (checked in `validation.js`/`inputs.js`), the private-payment-chain message received directly from a device peer has no such structural caps enforced before `JSON.stringify`, DB writes, and array iteration occur. A malicious paired device (or a device forwarding on their behalf) can send a `private_payments` hub message with `chains` containing very large arrays (many chains, and/or chains with huge `inputs`/`outputs` arrays), forcing the receiving wallet/hub to allocate large in-memory arrays, stringify them for storage, and iterate over them — proportional to attacker-controlled size, unconstrained.

### Impact Explanation
A crafted private-payment chain message can force the receiving node (wallet or hub relaying/handling private payments) to allocate memory and CPU proportional to attacker-controlled array sizes (chains count × inputs/outputs count per chain), with no anti-spam cap analogous to `MAX_INPUTS_PER_PAYMENT_MESSAGE`/`MAX_OUTPUTS_PER_PAYMENT_MESSAGE`/`MAX_UNIT_LENGTH`. This can exhaust memory or cause excessive processing time on the victim device/hub process, denying service to that node (and, if it is a hub, to all clients relying on it), matching the CWE-770 "Allocation of Resources Without Limits" pattern from the report, scaled to a Medium-severity node-level DoS.

### Likelihood Explanation
The trigger is reachable by an unprivileged paired device (or anyone who can get a `private_payments` message routed to a victim device/hub, as described in scope), requiring no special privileges, no prior on-chain confirmation, and no complex crafting beyond building large JSON arrays — a low-effort, directly reachable trigger.

### Recommendation
Add explicit bounds before processing `body.chains` in `wallet.js`'s `handlePrivatePaymentChains` and in `network.handleOnlinePrivatePayment`/`private_payment.js`: cap the number of chains, the number of elements per chain, and the size of `payload.inputs`/`payload.outputs` per element (reusing `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE`, `constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE`, and a reasonable max chain length/count), rejecting oversized messages before any JSON stringification, DB insertion, or iteration is performed.

### Proof of Concept
A malicious paired device sends, via the hub, a `private_payments` message:
```json
{
  "subject": "private_payments",
  "body": {
    "chains": [ /* N chains, each an array of M elements with payload.inputs/outputs containing K entries */ ]
  }
}
```
where N, M, and K are chosen large enough (e.g., tens of thousands of entries) to cause large memory allocations in `handlePrivatePaymentChains` → `handleOnlinePrivatePayment` → `JSON.stringify`/DB insert and in `divisible_asset.js`/`indivisible_asset.js`'s per-element loops, since no size limit analogous to `MAX_INPUTS_PER_PAYMENT_MESSAGE`/`MAX_OUTPUTS_PER_PAYMENT_MESSAGE` is enforced on these arrays before processing.

Note: I could not fully trace every intermediate size-limit check (e.g., whether `conf.MAX_MESSAGE_LENGTH`/websocket framing imposes an outer byte-size cap on the whole `private_payments` message before it reaches `handlePrivatePaymentChains`); if such a transport-level cap exists and is small enough, it would reduce/eliminate the exploitability of this specific path. This should be verified in the actual `network.js` message-receiving code (`sendJustsaying`/`handleJustsaying` message size limits) before treating this as fully confirmed.

### Citations

**File:** validation.js (L214-215)
```javascript
		if (objUnit.messages.length > constants.MAX_MESSAGES_PER_UNIT && !bGenesis)
			return callbacks.ifUnitError("too many messages");
```

**File:** constants.js (L43-48)
```javascript
exports.MAX_AUTHORS_PER_UNIT = 16;
exports.MAX_PARENTS_PER_UNIT = 16;
exports.MAX_MESSAGES_PER_UNIT = 128;
exports.MAX_SPEND_PROOFS_PER_MESSAGE = 128;
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_OUTPUTS_PER_PAYMENT_MESSAGE = 128;
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

**File:** wallet.js (L1020-1063)
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
```

**File:** network.js (L2376-2401)
```javascript
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
```

**File:** divisible_asset.js (L17-20)
```javascript
function validateAndSavePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	// we always have only one element
	validateAndSaveDivisiblePrivatePayment(conn, arrPrivateElements[0], callbacks);
}
```

**File:** divisible_asset.js (L30-72)
```javascript
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
```

**File:** divisible_asset.js (L86-100)
```javascript
	if (!ValidationUtils.isNonemptyArray(payload.inputs))
		return callbacks.ifError("no inputs");
	
	validation.initPrivatePaymentValidationState(
		conn, unit, message_index, payload, callbacks.ifError, 
		function(bStable, objPartialUnit, objValidationState){
		
			var arrAuthorAddresses = objPartialUnit.authors.map(function(author) { return author.address; } );

			function validateSpendProofs(sp_cb){

				var arrSpendProofs = [];
				async.eachSeries(
					payload.inputs,
					function(input, cb){
```

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
