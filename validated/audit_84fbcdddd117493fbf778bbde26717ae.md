### Title
Pre-validation property access on attacker-controlled private payment payload causes crash - ([File: network.js])

### Summary
`handleOnlinePrivatePayment()` in `network.js` dereferences `arrPrivateElements[0].payload.denomination` before it has verified that `payload` is a well-formed object, mirroring the xrdp bug class of accessing memory/fields before validating the input's shape/length.

### Finding Description
`handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks)` only checks that `arrPrivateElements` is a non-empty array via `ValidationUtils.isNonemptyArray(arrPrivateElements)` before immediately accessing nested fields: [1](#0-0) 

Specifically:
```
var unit = arrPrivateElements[0].unit;
var message_index = arrPrivateElements[0].message_index;
var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
```
`arrPrivateElements[0].payload` is dereferenced (`.denomination`) with no prior check that `arrPrivateElements[0]` is even an object, or that `.payload` exists and is itself an object. Only *after* this access does the function validate `unit`, `message_index`, and `output_index` with `ValidationUtils.isValidBase64` / `isNonnegativeInteger`.

This is analogous to the xrdp CVE: a field is read from an attacker-supplied structure before the code has validated that the structure has enough "space" (i.e., a defined `payload` object) to satisfy that read. If a peer sends a `private_payment` justsaying/message where the first chain element lacks a `payload` field, or where `payload` is `null`/a primitive, the line `arrPrivateElements[0].payload.denomination` throws a `TypeError: Cannot read properties of undefined (reading 'denomination')`.

By contrast, the hub-facing path `handlePrivatePaymentChains()` in `wallet.js` does perform a full structural check (`isNonemptyObject(e.payload)`, `isNonemptyString(e.payload.asset)`, etc.) on every chain element before calling into `network.handleOnlinePrivatePayment`: [2](#0-1) 

This shows that the codebase's own convention is to validate shape before use — the check is simply missing on the direct peer-to-peer path that reaches `handleOnlinePrivatePayment` directly (e.g. via the `private_payment` justsaying sent by any correspondent device/peer), matching the "payment counterparty" threat actor allowed by scope.

### Impact Explanation
An unhandled `TypeError` thrown synchronously inside a network message handler in Node.js, if not wrapped in try/catch by the caller, propagates as an uncaught exception, which in ocore's default (no domain/process supervisor recovering per-message) causes the process to crash. This is a remote, pre-authentication (i.e., prior to any wallet-level payload validation) denial-of-service vector reachable by anyone able to send a private-payment message to a node/hub, consistent with "a network unable to confirm new units" if the crashed process is a hub or peer relaying units.

### Likelihood Explanation
Any device or peer capable of initiating a private payment exchange (a normal, unprivileged wallet capability) can send a single `private_payment` message whose first chain element omits `payload` or sets it to a non-object value. No prior authentication or trust relationship beyond an established peer/device connection is required, and the crash occurs synchronously before any of the existing field-validity checks run.

### Recommendation
Add a structural guard before dereferencing nested fields in `handleOnlinePrivatePayment`, e.g.:
```js
if (!ValidationUtils.isNonemptyObject(arrPrivateElements[0]) || !ValidationUtils.isNonemptyObject(arrPrivateElements[0].payload))
    return callbacks.ifError("invalid private element or payload");
```
placed immediately after the `isNonemptyArray` check and before any `.payload.*` or `.unit`/`.message_index` access, mirroring the validation already performed in `wallet.js`'s `handlePrivatePaymentChains`.

### Proof of Concept
A peer sends the justsaying that is routed to `handleOnlinePrivatePayment` with content:
```json
[
  { "unit": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "message_index": 0 }
]
```
(i.e., the first element has no `payload` field.) The line
```js
var output_index = arrPrivateElements[0].payload.denomination ? ... : -1;
``` [3](#0-2) 
throws `TypeError: Cannot read properties of undefined (reading 'denomination')` before any of the subsequent `unit`/`message_index`/`output_index` validation runs, crashing the receiving node process if the exception is uncaught by the caller's error handling.

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

**File:** wallet.js (L955-978)
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
```
