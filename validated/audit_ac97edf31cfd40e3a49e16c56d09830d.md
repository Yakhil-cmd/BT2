### Title
Remote crash via uncaught `throw Error("no src coin amount")` on malformed private payment chain - (File: `validation.js`)

### Summary
`ocore` contains an analog of CVE-2023-37011's bug class: a message field that a remote, untrusted counterparty controls but that is not defensively validated before being consumed by code that uses a hard `throw Error(...)` (equivalent to an assertion) instead of a graceful validation-error callback. A malicious private-payment counterparty (or paired device) can send a malformed private payment chain that omits/corrupts the hidden output's `amount` field, causing an uncaught synchronous exception deep inside asynchronous validation code, which propagates to the process-wide `uncaughtException` handler and crashes the node.

### Finding Description
When a wallet processes an indivisible-asset private payment chain, `validatePrivatePayment` in [1](#0-0)  reads `prev_hidden_output = objPrevPrivateElement.payload.outputs[input.output_index]` — data taken directly from the previous chain element supplied by the sending peer — and only checks that it is *truthy* (`if (!prev_hidden_output) return callbacks.ifError(...)`). It never checks that `prev_hidden_output.amount` is a positive integer before copying it into `objValidationState.src_coin.amount`: [2](#0-1) 

This `objValidationState` (with the attacker-influenced `src_coin`) is then passed into `validation.validatePayment` → `validatePaymentInputsAndOutputs`. There, for private fixed-denomination assets, the code trusts the prepopulated `src_coin` and enforces its shape with hard assertions rather than callback errors: [3](#0-2) 

If `src_coin.amount` is missing or not a positive integer (e.g., attacker omits `amount` in the hidden output, or sets it to `null`/a string), the code executes `throw Error("no src coin amount")` synchronously instead of calling `cb(...)` with a normal validation error. Unlike the rest of the validation logic, which uniformly reports errors via callbacks (`return cb("...")`), this branch throws — the same "assertion instead of graceful rejection" pattern that CVE-2023-37011 describes for Open5GS's ASN.1 field handling.

This whole call chain is reachable from the network layer that handles private payments from wallet peers, e.g. `handleOnlinePrivatePayment` in [4](#0-3)  and `handlePrivatePaymentChains` in [5](#0-4) , neither of which wraps the downstream validation call in a `try/catch`. An uncaught exception thrown from inside this async chain is not caught by any local handler, and ultimately triggers Node's `uncaughtException` handler, which explicitly re-throws to crash the process: [6](#0-5) 

### Impact Explanation
A single malformed private-payment message from an untrusted counterparty/paired device causes an uncaught exception that crashes the receiving node/wallet process. Because `process.on('uncaughtException', ...)` deliberately re-throws to terminate the process (to avoid inconsistent state), this results in denial of service for the affected wallet/full node, matching the "node unable to confirm/validate new units" outcome class permitted by the rules. This can be triggered repeatedly to keep a targeted wallet/hub offline.

### Likelihood Explanation
Any wallet peer participating in a private payment (a normal, permitted interaction) can construct a private-payment chain and control the shape of the previous chain element's hidden outputs before this validation code executes basic type checks. The check only verifies the object is non-null/non-empty, not that `amount` is a valid positive integer, making this trivially reachable by crafting one malformed JSON message.

### Recommendation
- Before populating `objValidationState.src_coin`, validate `prev_hidden_output.amount` (and other fields relied upon downstream) with `ValidationUtils.isPositiveInteger` and return `callbacks.ifError(...)` on failure, instead of relying on the later `throw Error` in `validation.js`.
- Replace the `throw Error("no src_coin")/"no src_output"/"no denomination in src coin"/"no src coin amount"` assertions in `validatePaymentInputsAndOutputs` (validation.js:2416-2424) with calls to `cb("...")` so malformed input results in a normal validation rejection rather than a process crash.
- Wrap calls into asset/private-payment validation modules (`indivisible_asset.js`, `divisible_asset.js`) from `network.js`/`wallet.js` in defensive `try/catch` at the boundary where untrusted peer data is first processed, consistent with how other message handlers in `wallet.js`/`device.js` already catch parsing/verification exceptions.

### Proof of Concept
1. Act as a paired device / private-payment counterparty and send a wallet a private payment chain (`hub/message` subject `private_payments_v2`/similar, or direct `private_payment` P2P message) where the previous ("prev") chain element's `payload.outputs[output_index]` object is present (non-empty, e.g. contains only `output_hash`) but omits the `amount` field (or sets it to a non-numeric/non-positive value), while the head/tail elements otherwise construct a valid-looking `transfer` input referencing that prev output.
2. The receiving node processes the chain via `handleOnlinePrivatePayment`/`handlePrivatePaymentChains` → `indivisible_asset.validatePrivatePayment`, which copies the missing/invalid `amount` into `objValidationState.src_coin.amount` without validation (indivisible_asset.js:135-139).
3. Validation proceeds into `validation.js`'s `validatePaymentInputsAndOutputs`, hitting `if (!isPositiveInteger(src_coin.amount)) throw Error("no src coin amount");` (validation.js:2423-2424).
4. Because no caller in the chain catches this exception, it reaches Node's global `uncaughtException` handler, which logs the error and calls `throw err;`, terminating the process — denial of service against the targeted wallet/node.

### Citations

**File:** indivisible_asset.js (L95-139)
```javascript
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
```

**File:** validation.js (L2412-2424)
```javascript
					// for private fixed denominations assets, we can't look up src output in the database 
					// because we validate the entire chain before saving anything.
					// Instead we prepopulate objValidationState with denomination and src_output 
					if (objAsset && objAsset.is_private && objAsset.fixed_denominations){
						if (!objValidationState.src_coin)
							throw Error("no src_coin");
						var src_coin = objValidationState.src_coin;
						if (!src_coin.src_output)
							throw Error("no src_output");
						if (!isPositiveInteger(src_coin.denomination))
							throw Error("no denomination in src coin");
						if (!isPositiveInteger(src_coin.amount))
							throw Error("no src coin amount");
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

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```

**File:** wallet.js (L955-1079)
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
	
	if (conf.bLight)
		network.requestUnfinishedPastUnitsOfPrivateChains(arrChains); // it'll work in the background
	
	var assocValidatedByKey = {};
	var bParsingComplete = false;
	var cancelAllKeys = function(){
		for (var key in assocValidatedByKey)
			eventBus.removeAllListeners(key);
	};

	var current_message_counter = ++message_counter;

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
		}
	);
}
```
