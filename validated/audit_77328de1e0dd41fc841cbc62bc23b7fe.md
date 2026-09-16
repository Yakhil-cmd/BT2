### Title
Unauthenticated NULL/undefined dereference in `handleOnlinePrivatePayment` via crafted private-payment element missing `payload` - (File: network.js)

### Summary
`network.js`'s `handleOnlinePrivatePayment` dereferences `arrPrivateElements[0].payload.denomination` before verifying that `payload` is present, mirroring the libsndfile CVE-2018-19432 pattern of dereferencing a field without a preceding null-check, leading to an unhandled exception / crash of the processing path.

### Finding Description
`handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks)` in `network.js` only validates that `arrPrivateElements` is a non-empty array: [1](#0-0) 
```
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");

	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
```
It immediately accesses `arrPrivateElements[0].payload.denomination` without first checking that `.payload` is a non-empty object. If a peer/counterparty supplies a private-payment element whose `payload` field is `undefined`/`null` (e.g. `{unit: "...", message_index: 0}` with no `payload` key at all), this line throws a `TypeError: Cannot read properties of undefined (reading 'denomination')`.

The primary caller that is reachable from a remote/untrusted device is `wallet.js`'s `handlePrivatePaymentChains`, which does perform a thorough structural check on every chain element (`isNonemptyObject(e.payload)`, etc.) before calling `network.handleOnlinePrivatePayment` at: [2](#0-1) 
This guard currently blocks the most direct exploitation route through the wallet device-message path.

However, the dead/disabled direct-network `private_payment` justsaying handler in `network.js` shows the same unguarded call pattern was historically reachable directly from an unauthenticated peer over the wire before being disabled: [3](#0-2) 
```
case 'private_payment':
    return sendError(ws, `direct sending of private payments disabled, use chat instead`);
    if (!body)
        return;
    var arrPrivateElements = body;
    handleOnlinePrivatePayment(ws, arrPrivateElements, false, {...
```
Because the `return` on line 2897 executes unconditionally, this branch is currently dead code and not reachable, but it demonstrates that `handleOnlinePrivatePayment` was designed to be invoked with attacker-supplied `body` directly, with no validation of `payload` shape prior to the function's own (insufficient) checks. The function's own internal guard is a genuine bug regardless of caller-side mitigations, since it is a public-ish function reachable via multiple entry points (`network.exports.handleOnlinePrivatePayment`) and any future caller or refactor that skips the wallet.js-level pre-check reintroduces a crash.

### Impact Explanation
A malformed private-payment message with a missing/null `payload` field triggers an uncaught `TypeError` inside `handleOnlinePrivatePayment`. Depending on the call context (synchronous call inside a message-handling callback), this can propagate up and crash the Node.js process handling wallet/hub message dispatch, causing denial of service for the affected wallet/hub instance. This matches the "resource-only"/DoS class of the reference CVE, but is gated behind the wallet.js-level structural validation in the currently reachable production code path, which substantially reduces (but, given the fragility of relying on caller validation for a shared exported function, does not eliminate) the direct exploitability.

### Likelihood Explanation
Low-to-Medium: the only currently-live call path (`wallet.js: handlePrivatePaymentChains` → `network.handleOnlinePrivatePayment`) already validates `isNonemptyObject(e.payload)` for every chain element before invocation, blocking the crash in the actively used flow. The vulnerable line itself, however, has no local defense and is exported (`exports.handleOnlinePrivatePayment`), so any other current or future caller (or the dead code path shown above, if ever re-enabled) that does not perform the same pre-check would allow an unprivileged private-payment counterparty to trigger the crash with a single malformed message.

### Recommendation
Add an explicit type/shape check for `arrPrivateElements[0].payload` at the very top of `handleOnlinePrivatePayment`, before it is dereferenced, e.g.:
```js
if (!ValidationUtils.isNonemptyObject(arrPrivateElements[0].payload))
    return callbacks.ifError("no payload in first private element");
```
This makes the function robust independent of caller-side validation and closes the class of bug described in CVE-2018-19432 (dereference of a field that may be null/absent) at its root, rather than relying solely on upstream validation in `wallet.js`.

### Proof of Concept
Not applicable — since indexed code confirms the only currently reachable call path (`wallet.js:handlePrivatePaymentChains`) already guards against this input before calling the vulnerable function, a working exploit chain could not be constructed with confidence against current production wiring; this is provided as a defense-in-depth fix pointer, not a confirmed remotely-triggerable crash in the current build.

### Citations

**File:** network.js (L2376-2382)
```javascript
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
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
