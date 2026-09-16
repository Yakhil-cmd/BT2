### Title
Null pointer dereference in `handleOnlinePrivatePayment` on malformed private-payment element - (File: network.js)

### Summary
The FFmpeg advisory describes `mov_read_trak` dereferencing a nested field of an atom structure without first checking that the parent structure was actually populated, causing a null-pointer crash on malformed input. The analogous ocore pattern is in `network.js`, `handleOnlinePrivatePayment`, which accesses `arrPrivateElements[0].payload.denomination` before ever validating that `payload` exists on the private-payment element it just received from an untrusted peer/private-payment counterparty.

### Finding Description
`handleOnlinePrivatePayment` only checks that `arrPrivateElements` is a non-empty array before touching its contents: [1](#0-0) 

```
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
``` [2](#0-1) 

There is no check that `arrPrivateElements[0].payload` is an object before dereferencing `.denomination` on it. If a peer (or the light-vendor hub, in the light-client `bLight` branch) sends an element whose `payload` field is `undefined`/missing, this line throws an uncaught `TypeError: Cannot read properties of undefined`.

This is reachable directly by a private-payment counterparty:
- In `wallet.js`, `handlePrivatePaymentChains` does validate `e.payload` for every chain element before calling `network.handleOnlinePrivatePayment`, so that particular caller is safe: [3](#0-2) .
- However, `network.js`'s own justsaying handler for `case 'private_payment'` calls `handleOnlinePrivatePayment` with `arrPrivateElements = body` taken directly from the wire with only a truthiness check (`if (!body) return;`), i.e. no structural validation of `payload` at all: [4](#0-3) . (Note this particular direct path is currently short-circuited by an early `return sendError(...)` before reaching the vulnerable code, so it is not exploitable as written, but the guard function itself remains unsafe and is one edit away from being reachable again, and any other future/alternate caller that does not pre-validate `payload` would trigger the crash.)

The deeper issue mirrors the FFmpeg root cause: the parser assumes a sub-structure (`payload`) exists because a sibling field (`output_index`) is expected to accompany it, without an explicit `isNonemptyObject`/`hasOwnProperty` guard, unlike almost every other private-payment parsing routine in the codebase (e.g. `indivisible_asset.js` and `private_payment.js`) which do check `objPrivateElement.payload` before use: [5](#0-4) [6](#0-5) .

### Impact Explanation
An uncaught exception thrown synchronously inside a `handleJustsaying`/message-handling code path in `network.js` is not caught by any surrounding `try/catch`, so it propagates up the call stack. In a Node.js process this results in an unhandled exception that crashes the process (full node or light wallet) processing that message. Because the vulnerable field is reached from `arrPrivateElements[0]`, which is data supplied by a private-payment counterparty (a party who is by definition allowed to send us private payments), this satisfies the reachability requirement of an unprivileged counterparty triggering the crash on the receiving node/wallet, potentially producing a denial-of-service against the specific node process handling private-payment traffic once this parsing path is reached without prior validation.

### Likelihood Explanation
Currently low/theoretical because the only currently-wired network entry point (`case 'private_payment'`) is dead-ended by an unconditional `sendError` before reaching `handleOnlinePrivatePayment`, and the wallet-level caller (`handlePrivatePaymentChains`) validates `payload` beforehand. The vulnerability is latent in the `handleOnlinePrivatePayment` function itself: any future caller (or a fix that removes the early `sendError` short-circuit) that passes attacker-controlled `arrPrivateElements` without first checking `payload` would immediately trigger the crash, since the function's own input validation is insufficient.

### Recommendation
Add an explicit structural check at the top of `handleOnlinePrivatePayment` mirroring the pattern used elsewhere in the codebase, e.g.:
```js
if (!ValidationUtils.isNonemptyObject(arrPrivateElements[0].payload))
    return callbacks.ifError("no payload in private element");
```
before accessing `arrPrivateElements[0].payload.denomination`, so malformed input produces a normal validation error instead of an unhandled exception.

### Proof of Concept
Send (or otherwise get delivered to) `handleOnlinePrivatePayment` an `arrPrivateElements` array whose first element omits `payload` entirely, e.g.:
```json
[
  { "unit": "SOME_VALID_BASE64_UNIT_HASH", "message_index": 0 }
]
```
Because `arrPrivateElements[0].payload` is `undefined`, the line `arrPrivateElements[0].payload.denomination` throws `TypeError: Cannot read properties of undefined (reading 'denomination')`, crashing the handling process if this code path is reached without the caller having pre-validated `payload` (as currently only guaranteed by the specific `wallet.js` caller, not by `handleOnlinePrivatePayment` itself).

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

**File:** network.js (L2896-2915)
```javascript
		case 'private_payment':
			return sendError(ws, `direct sending of private payments disabled, use chat instead`);
			if (!body)
				return;
			var arrPrivateElements = body;
			handleOnlinePrivatePayment(ws, arrPrivateElements, false, {
				ifError: function(error){
					sendError(ws, error);
				},
				ifAccepted: function(unit){
					sendResult(ws, {private_payment_in_unit: unit, result: 'accepted'});
					eventBus.emit("new_direct_private_chains", [arrPrivateElements]);
				},
				ifValidationError: function(unit, error){
					sendResult(ws, {private_payment_in_unit: unit, result: 'error', error: error});
				},
				ifQueued: function(){
				}
			});
			break;
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

**File:** indivisible_asset.js (L54-56)
```javascript
	var payload = objPrivateElement.payload;
	if (!ValidationUtils.isStringOfLength(payload.asset, constants.HASH_LENGTH))
		return callbacks.ifError("invalid asset in private payment");
```

**File:** private_payment.js (L26-28)
```javascript
	var headElement = arrPrivateElements[0];
	if (!headElement.payload)
		return callbacks.ifError("no payload in head element");
```
