### Title
Unvalidated `payload.denomination` access causes crash (NULL/undefined pointer dereference) in `handleOnlinePrivatePayment` - (File: network.js)

### Summary
`network.js`'s `handleOnlinePrivatePayment` dereferences `arrPrivateElements[0].payload.denomination` before verifying that `payload` is actually an object, mirroring the class of bug in CVE-2020-35496 (`bfd_pef_scan_start_address` dereferencing a pointer without a prior existence check, crashing the consumer of attacker-supplied input).

### Finding Description
`handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks)` only validates that `arrPrivateElements` is a non-empty array before immediately computing: [1](#0-0) 
```
var unit = arrPrivateElements[0].unit;
var message_index = arrPrivateElements[0].message_index;
var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
```
There is no check that `arrPrivateElements[0].payload` exists or is a non-null object before accessing `.denomination` on it. `ValidationUtils.isNonemptyArray(arrPrivateElements)` only checks that the argument is an array with length > 0 — it says nothing about the shape of its elements [2](#0-1) . If `arrPrivateElements[0].payload` is `undefined` (or `null`), accessing `.denomination` throws an uncaught `TypeError`, which in Node.js escapes the synchronous call stack of the message handler and can crash/terminate the node process (a classic availability/DoS bug, structurally the same root cause as the binutils NULL dereference: missing existence check before dereferencing an optional/attacker-controlled field).

The only currently-wired caller that reaches this function with paired-device–controlled data is `wallet.js`'s `handlePrivatePaymentChains`, which pre-validates `isNonemptyObject(e.payload)` for every chain element before calling `network.handleOnlinePrivatePayment` [3](#0-2) [4](#0-3) , so that specific path is currently guarded. The direct peer-to-peer `justsaying` `'private_payment'` case in `network.js` that used to call `handleOnlinePrivatePayment` with fully unvalidated peer input has been disabled (`return sendError(...)` executes unconditionally before the call) [5](#0-4) . Because of this, I could not find a currently reachable, unauthenticated code path (from an unprivileged unit poster, AA author/trigger sender, asset issuer, or paired device) that invokes `handleOnlinePrivatePayment` with an `arrPrivateElements[0]` lacking `.payload`, given the guardrails present in every live caller I was able to enumerate. `handleSavedPrivatePayments`, which re-processes previously queued unhandled private payments, re-loads `arrPrivateElements` from the `unhandled_private_payments` table via `JSON.parse(row.json)` and passes it straight to `privatePayment.validateAndSavePrivatePaymentChain`, not to `handleOnlinePrivatePayment` — and `private_payment.js`'s `validateAndSavePrivatePaymentChain` does check `if (!headElement.payload) return callbacks.ifError(...)` before proceeding [6](#0-5) .

### Impact Explanation
If reached, an uncaught `TypeError` thrown synchronously inside a network message handler is not caught by any `try/catch` in `handleOnlinePrivatePayment`, and in Node.js an uncaught exception thrown outside of a promise/async context crashes the process by default, taking the node offline (availability impact analogous to the CVE, i.e., DoS of the node process). However, this only rises to the "network unable to confirm new units" bar the scan requires if it is reachable by an unauthenticated/unprivileged peer or device message with unvalidated `payload`, and I could not confirm such a live path with the tools available.

### Likelihood Explanation
Low-to-unknown: every caller of `handleOnlinePrivatePayment` I found in the indexed code performs a `payload` existence check (or the call path is dead code) before reaching this line, so exploitability requires either an as-yet-unfound caller, a future code change removing the guard, or a caller behind the light-client/hub-forwarding logic I could not fully trace (e.g., `handledChainsCache`/`forwardPrivateChainsToOtherMembersOf...` recursion paths, or `light/postJoint`-adjacent flows) that were not fully covered by the search results.

### Recommendation
Add an explicit guard in `handleOnlinePrivatePayment` before computing `output_index`:
```js
if (!ValidationUtils.isNonemptyObject(arrPrivateElements[0].payload))
    return callbacks.ifError("no payload in head private element");
```
This mirrors the defensive checks already present in `private_payment.js` (`validateAndSavePrivatePaymentChain`) and `wallet.js` (`handlePrivatePaymentChains`), making the function safe regardless of caller and closing the gap even if a new caller is introduced later without equivalent validation.

### Proof of Concept
Not verified end-to-end due to inability to confirm a live unauthenticated entry point. If a caller can be found that invokes `network.handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks)` with `arrPrivateElements = [{ unit: "<64-byte base64 unit>", message_index: 0 }]` (i.e., without a `payload` field, only satisfying `ValidationUtils.isNonemptyArray`), the process would throw `TypeError: Cannot read properties of undefined (reading 'denomination')` at `network.js:2382`, crashing the node.

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

**File:** network.js (L2896-2901)
```javascript
		case 'private_payment':
			return sendError(ws, `direct sending of private payments disabled, use chat instead`);
			if (!body)
				return;
			var arrPrivateElements = body;
			handleOnlinePrivatePayment(ws, arrPrivateElements, false, {
```

**File:** wallet.js (L959-972)
```javascript
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

**File:** wallet.js (L1020-1035)
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
```

**File:** private_payment.js (L23-34)
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
	
```
