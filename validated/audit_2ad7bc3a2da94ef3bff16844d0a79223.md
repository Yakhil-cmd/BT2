### Title
Missing `return` after failed hash calculation lets malformed private-payment chain reach validation twice, crashing the node - ([File: network.js])

### Summary
`handleSavedPrivatePayments()` in `network.js` processes private-payment chains that were queued from an untrusted counterparty (via `handleOnlinePrivatePayment`, reachable by any peer/device sending a "private_payments" message). When the head element's `payload` cannot be hashed by `objectHash.getBase64Hash()` (e.g. because it is missing required fields, contains unsupported types, or is circular), the code logs the error and calls `deleteHandledPrivateChain(...)` inside the `catch` block, but **does not `return`**. Execution falls through and unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, ...)` a second time on the very same malformed data that just failed basic hashing. Deep in the asset-validation modules (`divisible_asset.js` / `indivisible_asset.js` / `validation.js`), several code paths assume well-formed `payload.outputs` / `payload.inputs` arrays and dereference them without existence checks, causing an unhandled `TypeError` that propagates up through the synchronous call stack, out of any `try/catch`, and is caught only by the global `process.on('uncaughtException', ...)` handler in `network.js`, which explicitly **re-throws to crash the process**.

### Finding Description
The vulnerable flow:

1. `network.handleOnlinePrivatePayment()` (`network.js:2376-2441`) accepts an `arrPrivateElements` array from any peer/device with only shallow checks (`isNonemptyArray`, unit/message_index format), and stores the raw JSON in `unhandled_private_payments` for later processing: [1](#0-0) 

2. `handleSavedPrivatePayments()` later re-reads this stored JSON and calls `validateAndSave()`: [2](#0-1) 

Here, if `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` throws (attacker-controlled `payload` structure), the `catch` block handles the error path (delete + `cb()`) but does **not** `return`. Execution continues to build `key` (using the now-`undefined` `json_payload_hash`) and immediately calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` again, passing the same untrusted, already-known-malformed `arrPrivateElements` into the asset-validation pipeline.

3. `private_payment.js` → `divisible_asset.js`/`indivisible_asset.js` perform only partial structural checks (e.g. `validateDivisiblePrivatePayment` in `divisible_asset.js` checks `payload.asset` and `payload.inputs` but not `payload.outputs`) before later code paths iterate `payload.outputs.length` and index into `payload.inputs[0]` unconditionally. Because the head element already failed `getBase64Hash()` — meaning its structure is abnormal (missing/garbled fields, wrong types, or cyclic) — these downstream accesses can throw a plain, unguarded `TypeError` (e.g., "Cannot read properties of undefined (reading 'length')").

4. This exception is raised synchronously inside a callback invoked from `async.each`/`db.query`, i.e., outside any surrounding `try/catch`. It becomes a Node.js `uncaughtException`, which is handled in `network.js`: [3](#0-2) 
The handler explicitly re-throws (`throw err;`) "to crash the process to avoid ending up in an inconsistent state" — i.e., by design the whole node process terminates.

### Impact Explanation
Any correspondent device or peer that can send a "private payment" to a node (this is the direct wallet-to-wallet / hub relaying path used for private-asset transfers, textcoins, etc.) can craft a single private-payment chain whose head payload is malformed in a way that fails `objectHash.getBase64Hash()` yet is superficially accepted by the shallow checks in `handleOnlinePrivatePayment`. Once queued and later reprocessed by `handleSavedPrivatePayments`, the missing `return` after the `catch` guarantees the malformed data is fed into the validation pipeline a second time, and unguarded field access there crashes the entire ocore node process (full node, hub, or wallet backend). This matches the CVE's DoS class (malformed input handled while acting in a "receiving" role crashes the device/process, requiring a restart), and can be triggered remotely by a single unprivileged private-payment counterparty against any node that processes private payments — full nodes, hubs relaying private payments, and wallets.

### Likelihood Explanation
High reachability: no special privileges are needed — a private-payment counterparty (or any device paired/relaying via a hub) only needs to send one `private_payments` message containing a chain whose head `payload` is structurally broken enough to make `getBase64Hash` throw. The `handleOnlinePrivatePayment`/`unhandled_private_payments` queue mechanism guarantees `handleSavedPrivatePayments` will eventually process it. The bug (missing `return`) is deterministic — it always double-invokes `validateAndSavePrivatePaymentChain` on the same bad object, and the downstream code lacks defensive checks for the exact fields that would be malformed in a way that makes `getBase64Hash` fail.

### Recommendation
- Add a `return;` immediately after the `catch` block in `handleSavedPrivatePayments()` in `network.js` (after `deleteHandledPrivateChain(...)`) so malformed elements are not re-submitted to validation.
- Wrap the call to `privatePayment.validateAndSavePrivatePaymentChain(...)` (and its transitive calls into `divisible_asset.js`/`indivisible_asset.js`/`validation.js`) in a `try/catch` that reports a validation error instead of allowing an uncaught exception to escape.
- Add explicit structural validation (`payload.outputs` is a non-empty array, `payload.inputs` is non-empty and well-formed) at the very start of `validateDivisiblePrivatePayment`/`validatePrivatePayment`, before any field is dereferenced, so malformed private-payment chains are always rejected gracefully instead of crashing the process.

### Proof of Concept
1. As a paired device/private-payment counterparty, send a `private_payments` hub message (or a direct P2P `private_payment` message) containing one chain whose head element has a `payload` object that:
   - passes `isNonemptyArray(arrPrivateElements)` and `isValidBase64(unit,...)/isNonnegativeInteger(message_index)` checks in `handleOnlinePrivatePayment` (`network.js:2376-2389`), but
   - is structured (e.g., contains a circular reference, or a field type unsupported by `objectHash.getBase64Hash`, such as a function or `undefined` inside an object) so that `objectHash.getBase64Hash(payload, true)` throws.
2. The message is accepted and queued into `unhandled_private_payments` via `savePrivatePayment()`.
3. When `handleSavedPrivatePayments()` runs (triggered periodically/on new unit), it reads the row, calls `validateAndSave()`, `getBase64Hash` throws and is caught, but the missing `return` lets execution reach `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, ...)` a second time with the same malformed payload, hitting an unguarded field access deep in `divisible_asset.js`/`indivisible_asset.js`/`validation.js` and throwing an uncaught `TypeError`, which is caught by the `process.on('uncaughtException', ...)` handler that re-throws and terminates the node.

(Note: exact minimal payload shape needed to make `getBase64Hash` throw was not verified end-to-end in this session — a Devin session with the ability to run the code against `object_hash.js` would be needed to confirm the precise malformed structure and the exact downstream `TypeError` line.)

### Citations

**File:** network.js (L2376-2402)
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
```

**File:** network.js (L2455-2478)
```javascript
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
