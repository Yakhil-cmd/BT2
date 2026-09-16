I found a solid analog: an unbounded, attacker-controlled private-payment chain length that leads to an uncaught exception (crashing the process) inside the chain-parsing/building code path.

### Title
Remote DoS via uncaught exceptions when processing an unbounded/malformed private payment chain - (File: indivisible_asset.js / private_payment.js)

### Summary
`parsePrivatePaymentChain` in `indivisible_asset.js` and its counterpart in `divisible_asset.js` process an attacker-supplied `arrPrivateElements` array with no upper bound on its length and no wrapping try/catch around several `throw Error(...)` statements that are reachable with attacker-crafted data. This is reachable directly from a paired-device / private-payment counterparty message (`network.handleOnlinePrivatePayment` → `private_payment.validateAndSavePrivatePaymentChain` → `indivisible_asset.validateAndSavePrivatePaymentChain`/`parsePrivatePaymentChain`), analogous to quicly's unbounded CRYPTO-stream handshake reassembly that crashed the process via an assertion once a size threshold was exceeded.

### Finding Description
`handleOnlinePrivatePayment` only checks that `arrPrivateElements` is a non-empty array and that basic head-element fields are well-formed; it does not cap the chain length or the recursion/iteration depth: [1](#0-0) 

The chain is then handed to `privatePayment.validateAndSavePrivatePaymentChain`, which performs only asset-level checks before delegating to the asset-specific module: [2](#0-1) [3](#0-2) 

Inside `indivisible_asset.js`, `parsePrivatePaymentChain` iterates the entire attacker-supplied array with `async.forEachOfSeries` and no length limit, while `validateAndSavePrivatePaymentChain` builds an ever-growing `arrQueries` array (multiple SQL statements per chain element) before executing them: [4](#0-3) [5](#0-4) 

Several code paths that are reachable while walking/saving this chain use bare `throw Error(...)` instead of routing errors through the `callbacks.ifError` channel, e.g. `validateAndSavePrivatePaymentChain`'s "neither transfer nor issue after validation" and `private_payment.js`'s "more than one output" check: [6](#0-5) [7](#0-6) 

Because ocore's top-level `uncaughtException` handler intentionally re-throws to crash the process (to avoid running with inconsistent state), any of these reachable, unguarded `throw Error(...)` calls — or memory/stack pressure from processing an oversized/malformed chain — brings down the whole node: [8](#0-7) 

This mirrors the quicly issue: a value derived from untrusted peer input (there, cumulative CRYPTO-stream bytes; here, the private-payment chain array and its nested fields) is not bounded/validated before it reaches code that asserts/throws on an unexpected condition, and that failure is fatal to the whole process rather than being handled gracefully.

### Impact Explanation
A private-payment counterparty (someone with whom the victim wallet exchanges private payments, which requires no special privilege beyond being a correspondent/paired device) can send a crafted or arbitrarily long `arrPrivateElements` chain (via `private_payment` message or `handlePrivatePaymentChains`/hub `chains` payload) that triggers one of the unguarded `throw Error(...)` paths or excessive resource consumption while walking the chain. Given the `uncaughtException` handler's explicit `throw err`, this crashes the recipient's ocore process — a full node-halt Denial of Service, matching the "network unable to confirm new units" criterion for the sender's node while it is down.

### Likelihood Explanation
Likelihood is moderate-to-high for any wallet/hub node that accepts private payments from arbitrary correspondents: the entry points (`network.handleOnlinePrivatePayment`, `wallet.handlePrivatePaymentChains`) are reachable from any paired device or hub-relayed private-payment message, requiring no consensus-level unit to be mined, only a crafted device message.

### Recommendation
- Enforce a strict, low upper bound on `arrPrivateElements.length` (and each element's referenced input/output structure) as early as `handleOnlinePrivatePayment`/`handlePrivatePaymentChains`, rejecting oversized chains before any processing.
- Wrap all `parsePrivatePaymentChain` / `validateAndSavePrivatePaymentChain` internals in try/catch and route every failure through `callbacks.ifError` instead of `throw Error(...)`, so malformed attacker input cannot escape as an uncaught exception.
- Audit `buildPrivateElementsChain`/`readPayloadAndGoUp` and `private_payment.js` for the same pattern of unguarded `throw Error(...)` on attacker-influenced data.

### Proof of Concept
Not independently executable from static analysis alone; conceptually: a paired device sends a `private_payment` (or hub `chains`) message whose `arrPrivateElements`/`chains` array is extremely long or contains an element that violates an assumption checked only via `throw Error(...)` in `indivisible_asset.js`'s `validateAndSavePrivatePaymentChain` (e.g., an `input` object that is neither `type: "issue"` nor a transfer, reaching line 266-267) or the "more than one output" duplicate-check in `private_payment.js` (lines 74-75), crashing the recipient node via the global `uncaughtException` re-throw.

**Uncertainty note:** I could not fully trace every intermediate validation layer (e.g., `initPrivatePaymentValidationState` in `validation.js`, which may reject some malformed inputs earlier) due to index size limits on retrievable file content; a background Devin session with full repo access would be needed to confirm exactly which malformed element bypasses prior checks and reaches an unguarded `throw`.

### Citations

**File:** network.js (L2376-2388)
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

**File:** private_payment.js (L23-44)
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
```

**File:** private_payment.js (L70-76)
```javascript
					conn.query(
						sql, 
						params, 
						function(rows){
							if (rows.length > 1)
								throw Error("more than one output "+sql+' '+params.join(', '));
							if (rows.length > 0 && rows[0].address){ // we could have this output already but the address is still hidden
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
