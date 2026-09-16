## Title
NULL/undefined dereference on unchecked `payload.inputs[0]` element crashes the node process - (File: `validation.js`)

## Summary
`CVE-2021-39516` is a NULL pointer dereference in libjpeg's `HuffmanDecoder::Get()`: the decoder blindly dereferences a table/pointer without validating it, causing the process to crash (DoS) when an attacker supplies malformed input. The ocore analog is in the asset-payment validation path, where `payload.inputs[0]` is dereferenced without first checking that the array element is a non-null object, allowing any unprivileged unit poster to crash the full node process via `process.on('uncaughtException')`'s deliberate `throw err`.

## Finding Description
`validatePayment()` validates an inline `payment` message payload. It only checks that `payload.inputs` is a non-empty array via `isNonemptyArray(payload.inputs)`: [1](#0-0) 

`isNonemptyArray` only checks `Array.isArray` and length, never that the individual elements are objects: [2](#0-1) 

For asset (non-base) payments, after loading the asset, the code directly dereferences the first array element to read `.type`, *before* any per-element type/shape validation is performed: [3](#0-2) 

If an attacker crafts a unit whose `payment` message has `payload.asset` set and `payload.inputs = [null, ...]` (a `null` in place of the first input object), `payload.inputs[0].type` throws `TypeError: Cannot read properties of null (reading 'type')`. This is exactly analogous to the libjpeg bug class: a parser dereferences an element from attacker-controlled structured input without first validating it is non-null.

Contrast this with the safe path taken later inside `validatePaymentInputsAndOutputs`, where each input element *is* checked with `isNonemptyObject(input)` before use — but that check happens only inside the `async.forEachOfSeries` loop, which is reached after the vulnerable line 2099 access: [4](#0-3) 

The thrown exception occurs synchronously inside the callback of `storage.loadAssetWithListOfAttestedAuthors`'s `conn.query`, deep in an async I/O callback chain that is not wrapped in a `try/catch` by `validation.js`. Because it's an exception thrown from inside a database-callback (not caught anywhere up the stack), it becomes an uncaught exception at the process level.

The codebase's own global exception handler in `network.js` explicitly documents that any uncaught exception is fatal by design: [5](#0-4) 

## Impact Explanation
Any single unprivileged unit poster can submit one unit that trips this condition. Because the process-wide `uncaughtException` handler re-throws to intentionally crash the process, the entire hub/full node terminates. This is a "network unable to confirm new units" / node-availability impact — the same class of concrete, unauthenticated Denial-of-Service outcome accepted by the validation rules for this exercise (crashing the whole node), directly mirroring the libjpeg DoS-via-null-dereference bug class. It does not itself cause fund loss or double-spend, but it satisfies the "network unable to confirm new units" acceptance criterion because the crashed node stops processing/validating/relaying units until manually restarted.

## Likelihood Explanation
High likelihood of exploitability by any actor able to compose and submit a unit (an unprivileged unit poster):
- The malformed field (`payload.inputs = [null]`) is a trivially crafted JSON value.
- No special asset knowledge, private key control over specific balances, or witness/oracle role is required — merely an asset unit reference (`payload.asset` being a valid-length base64 string) and the crafted `inputs` array.
- No earlier validation stage (`hasValidPayloadHashes`, `isObjectWellFormed`, `isTooDeeplyNestedOrHasTooManyNodes`) rejects a `null` element inside an array field; these checks target string well-formedness and nesting depth/count, not element-type safety of arrays like `inputs`.
- The vulnerable line executes unconditionally on the asset-payment validation path for any payment referencing an existing asset.

## Recommendation
Add an explicit shape check on `payload.inputs[0]` (and generally validate `payload.inputs` elements are non-null objects) before any property access in `validatePayment()`, e.g., replace or precede line 2099 with:
```js
if (!isNonemptyObject(payload.inputs[0]))
    return callback("first input must be a non-empty object");
var bIssue = (payload.inputs[0].type === "issue");
```
More robustly, move (or duplicate) the `isNonemptyObject(input)` check from `validatePaymentInputsAndOutputs`'s `forEachOfSeries` loop to run over `payload.inputs` immediately after the `isNonemptyArray` check in `validatePayment`, before any indexed access, so both the base and asset payment code paths are protected uniformly.

## Proof of Concept
Construct and submit a unit with a `payment` message referencing a valid, existing asset, where the first input element is `null`:
```json
{
  "app": "payment",
  "payload_location": "inline",
  "payload": {
    "asset": "<44-char base64 asset unit hash>",
    "inputs": [null],
    "outputs": [ { "address": "<VALID_ADDRESS>", "amount": 1000 } ]
  }
}
```
When validation reaches `validatePayment()` → `payload.inputs[0].type` at `validation.js:2099`, `payload.inputs[0]` is `null`, causing an uncaught `TypeError`. This exception is not caught anywhere in the validation call chain, propagates to Node's `uncaughtException` handler in `network.js:4530-4543`, and the process is deliberately terminated with `throw err`, crashing the full node/hub.

### Citations

**File:** validation.js (L2059-2067)
```javascript
// used for both public and private payments
function validatePayment(conn, payload, message_index, objUnit, objValidationState, callback){

	if (!isNonemptyObject(payload))
		return callback("payment must be a non-empty object");
	if (!isNonemptyArray(payload.inputs))
		return callback("no inputs");
	if (!isNonemptyArray(payload.outputs))
		return callback("no outputs");
```

**File:** validation.js (L2084-2100)
```javascript
	storage.loadAssetWithListOfAttestedAuthors(conn, payload.asset, objValidationState.last_ball_mci, arrAuthorAddresses, objValidationState.bAA, function(err, objAsset){
		if (err)
			return callback(err);
		if (hasFieldsExcept(payload, ["inputs", "outputs", "asset", "denomination"]))
			return callback("unknown fields in payment message");
		if (objAsset.fixed_denominations){
			if (!isPositiveInteger(payload.denomination))
				return callback("no denomination");
		}
		else{
			if ("denomination" in payload)
				return callback("denomination in arbitrary-amounts asset")
		}
		if (!!objAsset.is_private !== !!objValidationState.bPrivate)
			return callback("asset privacy mismatch");
		var bIssue = (payload.inputs[0].type === "issue");
		var issuer_address;
```

**File:** validation.js (L2239-2243)
```javascript
	async.forEachOfSeries(
		payload.inputs,
		function(input, input_index, cb){
			if (!isNonemptyObject(input))
				return cb("input must be a non-empty object");
```

**File:** validation_utils.js (L68-70)
```javascript
function isNonemptyArray(arr){
	return (Array.isArray(arr) && arr.length > 0);
}
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
