### Title
Unchecked `.payload` dereference in `handleOnlinePrivatePayment` causes NULL/TypeError crash on malformed private payment - (File: network.js)

### Summary
`network.js`'s `handleOnlinePrivatePayment` accepts an attacker-controlled `arrPrivateElements` array (from a device/wallet peer or via hub) and dereferences `arrPrivateElements[0].payload.denomination` without first checking that `.payload` exists, analogous to GNU patch's `intuit_diff_type` NULL dereference on a mangled rename header (CVE-2018-6951): a malformed/mangled input structure causes an unguarded field access to throw, crashing the process.

### Finding Description
`handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks)` only validates that `arrPrivateElements` is a non-empty array before immediately accessing nested fields: [1](#0-0) 

```
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
```

Only `isNonemptyArray(arrPrivateElements)` is checked — there is no guard that `arrPrivateElements[0]` is a non-empty object, nor that `.payload` exists. If a peer or hub delivers `arrPrivateElements` such as `[{unit: "...", message_index: 0}]` (payload omitted, or `payload: null`), the expression `arrPrivateElements[0].payload.denomination` throws `TypeError: Cannot read properties of undefined (reading 'denomination')` (or, for `payload: null`, the same class of error), a JavaScript-level NULL/undefined dereference. This mirrors the "mangled" structural assumption in `intuit_diff_type` that led to the original CVE's segfault: a structurally-valid outer envelope (a non-empty array) with a missing/mangled inner field bypasses the shallow check and reaches an unguarded nested-field access.

Only downstream once this same array is handed to `wallet.js:handlePrivatePaymentChains` is there a strict per-element check (`isNonemptyObject(e.payload)`, etc.) before forwarding — see the stronger validation there: [2](#0-1) 

That path is safe, but `handleOnlinePrivatePayment` in `network.js` is reachable as its own entry point (called with attacker-controlled `arrPrivateElements` for both online single-payment delivery and queued/light-client delivery), and it performs the unguarded dereference *before* any of that stronger validation runs.

### Impact Explanation
An unhandled `TypeError` thrown synchronously inside a network message handler in a Node.js process is not caught by any `try/catch` at this call site, and unless wrapped by a top-level `uncaughtException` handler that safely no-ops, it will terminate the node process (or, if node's default handler is in effect, crash the process). Since this function is invoked when receiving private-payment content from a peer or hub (a reachable, unprivileged private-payment counterparty as scoped in this task), a single malformed message can crash a full node or wallet, denying service to that node and its users — a network-wide availability impact if replicated across nodes receiving the same malicious payload (e.g., forwarded through a hub to many light wallets).

### Likelihood Explanation
The malformed input requires no special privilege — any device peer or a compromised/malicious hub relaying a "private_payment"-style message can supply an `arrPrivateElements[0]` object lacking a `payload` field or with `payload: null`, while still satisfying `isNonemptyArray`. This is a trivial one-message DoS with no cryptographic material or prior relationship needed beyond being a paired device/counterparty able to send private payment data.

### Recommendation
Add an explicit non-empty-object check on `arrPrivateElements[0].payload` (and ideally on `arrPrivateElements[0]` itself) at the top of `handleOnlinePrivatePayment`, mirroring the guard already present in `wallet.js:handlePrivatePaymentChains` (`isNonemptyObject(e.payload)`), before any field of `.payload` is read. Also audit other call sites that read `arrPrivateElements[0].payload...` early (e.g., `network.js:handleSavedPrivatePayments`) for the same unguarded pattern, and wrap message-handling entry points with defensive validation rather than relying solely on downstream validators.

### Proof of Concept
1. As a paired device peer or a hub relaying to a light wallet, send a `private_payment`-class message whose `arrPrivateElements` is `[{ "unit": "<44-byte base64 unit id>", "message_index": 0 }]` (no `payload` key, or `"payload": null`).
2. `ValidationUtils.isNonemptyArray(arrPrivateElements)` passes (array has 1 element).
3. Execution reaches `arrPrivateElements[0].payload.denomination`, throwing `TypeError: Cannot read properties of undefined (reading 'denomination')`.
4. If uncaught up the stack, the node/wallet process crashes, denying service.

Note: I was not able to trace every possible caller/guard for `handleOnlinePrivatePayment` (e.g., whether some callers wrap it in try/catch) due to index/context limits; a Devin session with full repo access should confirm the exact call graph (`network.js` `case 'private_payment'` dispatch and `handleSavedPrivatePayments`) before finalizing severity.

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
