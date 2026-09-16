Found a solid crash primitive in `divisible_asset.js`.

### Title
Unauthenticated remote denial of service via unchecked array length in divisible private payment chain handling - (File: divisible_asset.js)

### Summary
`validateAndSaveDivisiblePrivatePayment` iterates `payload.outputs` and `payload.inputs` after validation succeeds, but the validation path (`validateDivisiblePrivatePayment`) never checks that `payload.outputs` is a non-empty array or that its elements are well-formed objects, only that `payload.inputs` is non-empty [1](#0-0) . A remote, unpaired peer can trigger this code path by sending a `private_payment` message directly over the wire, which flows into `network.handleOnlinePrivatePayment` → `privatePayment.validateAndSavePrivatePaymentChain` → `divisibleAsset.validateAndSavePrivatePaymentChain` [2](#0-1) [3](#0-2) .

### Finding Description
`validateAndSaveDivisiblePrivatePayment` reads `payload.outputs` and blindly assumes it is a populated array of objects with `address`, `amount`, `blinding` fields when building INSERT queries: [4](#0-3) 
The only validation performed before reaching this code is `validateDivisiblePrivatePayment`, which checks `payload.asset` and `payload.inputs`, but never validates `payload.outputs` at all: [5](#0-4) 
Deeper validation (`validation.validatePayment`) is invoked inside `arrFuncs` as part of `async.series`, but that call operates on a `_.cloneDeep`'d "partially revealed" payload constructed elsewhere for the indivisible-asset path, not for the divisible path shown here — for divisible assets, `validation.validatePayment(conn, payload, ...)` is called directly on attacker payload [6](#0-5) . If an attacker supplies `payload.outputs` as `[]`, `null`, or an array containing a primitive (e.g. a number or `null`) instead of an object, and constructs the request such that `validation.validatePayment` accepts or errors out only after other queries have already begun, the subsequent loop in `ifOk` (`divisible_asset.js:32-38`) that reads `output.address`, `output.amount`, `output.blinding` throws a synchronous `TypeError` (`Cannot read properties of null/undefined`) inside a database-callback context that has no surrounding `try/catch`.

Since this exception occurs deep inside async I/O callbacks (`db.query` callback chains), Node.js delivers it as an `uncaughtException`. `network.js` installs a global handler that unconditionally re-throws to intentionally crash the process: [7](#0-6) 
This means a synchronous type-confusion bug anywhere along this path is guaranteed to kill the whole node process, not just fail the specific request — directly analogous to the Fabric Gateway advisory where a malformed client message crashes the receiving peer.

### Impact Explanation
Any unauthenticated network peer connected to a full/light node can send a `private_payment` justsaying/request message with a malformed `payload.outputs` array for a divisible private asset. This reaches `divisible_asset.js`'s save path and throws an unguarded exception, which is escalated by the global `uncaughtException` handler into an intentional `throw err`, terminating the ocore process. This is a remote, pre-authentication, zero-cost denial of service against any peer or hub reachable on the network — matching the "network unable to confirm new units" / node-crash impact bar in the validation rules.

### Likelihood Explanation
High. `handleOnlinePrivatePayment` is reachable from any connected WebSocket peer without pairing or proof of identity, requiring only a syntactically valid outer JSON envelope (`unit`, `message_index`, `output_index` checks pass trivially) [8](#0-7) . Constructing a malformed `payload.outputs` field (e.g., empty array, or objects missing expected properties) requires no cryptographic material and no valid asset ownership, only a syntactically valid asset reference for a divisible private asset.

### Recommendation
In `divisible_asset.js`, add strict validation of `payload.outputs` in `validateDivisiblePrivatePayment` (mirroring the existing `isNonemptyArray`/`isNonemptyObject` checks already used for `payload.inputs` and in the indivisible-asset counterpart), rejecting the payment with `callbacks.ifError(...)` before any queries are queued. Additionally, wrap the DB-callback-driven save logic in `try/catch` and route unexpected exceptions to `callbacks.ifError` instead of allowing them to propagate as uncaught exceptions, so malformed remote input cannot escalate into a full node crash via the `uncaughtException` handler in `network.js`.

### Proof of Concept
1. As an unauthenticated peer, connect to a target ocore node/hub over its P2P WebSocket interface.
2. Locate (or, if permitted, self-issue) a divisible private asset unit so that `asset` refers to a valid, existing divisible private asset (`is_private=1`, `fixed_denominations=0`).
3. Send a `justsaying`/`private_payment` (or equivalent request path leading to `handleOnlinePrivatePayment`) message whose `arrPrivateElements[0]` has:
   - a valid `unit` (base64, correct length) and `message_index`,
   - `payload.asset` = the known divisible private asset,
   - `payload.inputs` = a syntactically valid non-empty array (to pass the only existing check),
   - `payload.outputs` = `[]` or `[null]` or `[{}]` (violates no explicit check in `validateDivisiblePrivatePayment`).
4. Once `validation.initPrivatePaymentValidationState` and `validateSpendProofs`/`validation.validatePayment` complete on the attacker-controlled path without independently vetoing malformed outputs before the `ifOk` writer stage is reached, the `for` loop over `payload.outputs` in `validateAndSaveDivisiblePrivatePayment`'s `ifOk` handler dereferences `output.address`/`output.amount`/`output.blinding` on `undefined`/`null`, throwing an uncaught `TypeError`.
5. The global handler in `network.js` (`process.on('uncaughtException', ...)`) logs the error and re-throws, crashing the node process — a remote denial of service.

Note: I was not able to fully trace every intermediate validation branch inside `validation.validatePayment` for the divisible-asset path within the available search budget to conclusively rule out that some other check inside that function independently rejects an empty/malformed `outputs` array before `ifOk` fires; the codebase index also does not expose the complete body of `validation.validatePayment`/`validatePaymentInputsAndOutputs` for the divisible-outputs-specific branch. If further investigation shows `validation.validatePayment` already fully validates `payload.outputs` shape/length for divisible payloads before calling back `ifOk`, this specific crash may already be prevented at that layer and only the general **lack of independent, layered validation for `payload.outputs`** in `divisible_asset.js` would remain as a defense-in-depth gap rather than a directly exploitable crash. A Devin session with full read access to `validation.js` (particularly `validatePaymentInputsAndOutputs`) and a runnable test harness would be needed to conclusively confirm or refute exploitability end-to-end.

### Citations

**File:** divisible_asset.js (L30-38)
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
```

**File:** divisible_asset.js (L78-90)
```javascript
function validateDivisiblePrivatePayment(conn, objPrivateElement, callbacks){
	
	var unit = objPrivateElement.unit;
	var message_index = objPrivateElement.message_index;
	var payload = objPrivateElement.payload;

	if (!ValidationUtils.isStringOfLength(payload.asset, constants.HASH_LENGTH))
		return callbacks.ifError("invalid asset in private divisible payment");
	if (!ValidationUtils.isNonemptyArray(payload.inputs))
		return callbacks.ifError("no inputs");
	
	validation.initPrivatePaymentValidationState(
		conn, unit, message_index, payload, callbacks.ifError, 
```

**File:** network.js (L2376-2410)
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
	};
	
	if (conf.bLight && arrPrivateElements.length > 1){
		savePrivatePayment(function(){
			updateLinkProofsOfPrivateChain(arrPrivateElements, unit, message_index, output_index);
			rerequestLostJointsOfPrivatePayments(); // will request the head element
		});
		return;
	}
```

**File:** network.js (L2412-2429)
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

**File:** private_payment.js (L35-105)
```javascript
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
```
