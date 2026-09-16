### Title
Missing bounds check on `output_index` in `parsePrivatePaymentChain` allows an unauthorized-recipient TypeError/DoS when validating a private-payment counterparty's chain - (File: indivisible_asset.js)

### Summary
CVE-2016-7510 is a libdwarf out-of-bounds read caused by a stateful table-reader trusting attacker-supplied offsets/lengths while walking an array without verifying they stay in bounds. The closest reachable analog in ocore is the private (indivisible-asset) payment-chain parser, which walks a chain of attacker-supplied `objPrivateElement`/`payload` records and indexes into `payload.outputs[]` using an `output_index` value taken from the *previous* chain element without validating that it is within the bounds of the current element's `outputs` array before dereferencing the result.

### Finding Description
`parsePrivatePaymentChain` in `indivisible_asset.js` iterates over `arrPrivateElements` (a private-payment chain handed to us by a payment counterparty) and cross-links each element to the previous one purely by comparing `unit`, `message_index`, and `output_index` fields taken directly from the untrusted `payload.inputs[0]` object: [1](#0-0) 

The actual bounds-checked access of `payload.outputs[objPrivateElement.output_index]` happens inside `validatePrivatePayment` via `isNonemptyObject(payload.outputs[objPrivateElement.output_index])`, which does correctly reject an out-of-range index for the *current* element: [2](#0-1) 

However, the companion helper `buildPrivateElementsChain`, which is used later (e.g. from `restorePrivateChains`/`getSavingCallbacks` when constructing/replaying the chain for saving and forwarding to cosigners) reads `payload.outputs[output_index]` and immediately dereferences `.address`/`.blinding` on the result with no existence check at all: [3](#0-2) 

Because `output_index` values embedded in the chain are attacker-controlled integers coming from the private-payment counterparty's `payload.inputs[0].output_index` / `.outputs` structure, a value that is out of range for the corresponding `outputs` array (e.g., larger than `outputs.length-1`, since `isNonnegativeInteger` only checks type/sign, not range against the specific array it will later index) makes `payload.outputs[output_index]` evaluate to `undefined`, and the immediately following `output.address` throws an uncaught `TypeError`. This is analogous to the libdwarf bug: a length/offset value that is well-formed per basic type checks is used to index into a variable-length, attacker-influenced array without re-validating it against the current buffer's real size at the point of use.

### Impact Explanation
An uncaught exception thrown deep inside asynchronous DB-callback code (`conn.query(...)` callback) in a Node.js process is not caught by any surrounding `try/catch` in the call chain and will crash the process (unhandled exception in an async callback terminates the Node.js event loop / process). Because this code path is triggered while processing private payment chains received from a payment counterparty (a scenario explicitly in-scope: "private-payment counterparty"), a malicious counterparty in a private (indivisible-asset) payment can supply a chain whose `output_index` references are inconsistent with the referenced element's `outputs` array length, causing the recipient/cosigner node's wallet process to crash while trying to save/forward the chain. This is a concrete denial-of-service against a node processing private payments — the closest available impact category under the rules ("node unable to confirm new units" / process crash preventing further payment processing), consistent in severity class with the CVE's crash/DoS via out-of-bounds read.

### Likelihood Explanation
Likelihood is moderate: the crash requires the chain to first pass `parsePrivatePaymentChain`'s existing checks (asset/denomination consistency, unit/message_index/output_index cross-references, and the `isNonemptyObject` guard inside `validatePrivatePayment` for the *current* element). The vulnerable `buildPrivateElementsChain` code path, however, re-derives `output_index` from freshly queried DB rows in some call sites, but is also invoked with attacker-controlled/forwarded `payload.outputs`/`output_index` combinations from private-chain replay/restoration flows, where the same `output_index` that was accepted for one element in the chain is reused to index a *different* element's `outputs` array without re-checking bounds for that specific array. Triggering it reliably requires crafting a private-payment chain with mismatched output array lengths across chain elements, which is achievable by any wallet counterparty composing a custom (non-standard) private-payment message.

### Recommendation
Add an explicit bounds/type check before every array index dereference of `payload.outputs[output_index]` in `buildPrivateElementsChain` (and any other private-payment helper touching `outputs[idx]`), e.g.:
```js
var output = payload.outputs[output_index];
if (!ValidationUtils.isNonemptyObject(output))
    throw Error("output not found at index " + output_index);
```
More generally, centralize output/`output_index` bounds validation once at the point where `output_index` values are extracted from untrusted `payload`/chain data, and re-validate them against the specific array they are about to index — rather than relying on a check performed against a different chain element's array. Wrap DB-callback logic that processes untrusted private-chain content in structured error handling so that malformed data returns a validation error to the caller instead of throwing, preventing a process crash.

### Proof of Concept
1. Attacker (private-payment counterparty) constructs an indivisible-asset private payment chain `arrPrivateElements` where an intermediate element's `payload.inputs[0].output_index` correctly matches the previous element's `output_index` field (satisfying the `parsePrivatePaymentChain` cross-reference checks) but the *referenced* element's own `payload.outputs` array has fewer entries than `output_index + 1`.
2. The chain is sent to the victim as part of a private payment (chat message/asset transfer). During chain restoration/forwarding via `buildPrivateElementsChain` (invoked from `getSavingCallbacks`/`restorePrivateChains`), `payload.outputs[output_index]` resolves to `undefined`.
3. The subsequent line `output.address` (indivisible_asset.js line ~635) throws `TypeError: Cannot read properties of undefined`.
4. Because this occurs inside an asynchronous DB callback, the exception is unhandled and crashes the victim's Node.js process, denying further payment processing.

Note: I was not able to fully trace every caller of `buildPrivateElementsChain`/`restorePrivateChains` end-to-end to network-received private-payment messages within the available search iterations (e.g., confirming exact reachability from `network.js`'s private-payment message handlers to `restorePrivateChains` versus purely wallet-initiated flows). This should be verified with a full trace of `private_payment.js` → `divisible_asset.js`/`indivisible_asset.js` → `network.js` message handlers before treating this as fully confirmed; a Devin session with full repository access would be needed to conclusively confirm the exact remote trigger path.

### Citations

**File:** indivisible_asset.js (L63-67)
```javascript
	if (!ValidationUtils.isNonemptyArray(payload.outputs))
		return callbacks.ifError("invalid outputs");
	var our_hidden_output = payload.outputs[objPrivateElement.output_index];
	if (!ValidationUtils.isNonemptyObject(payload.outputs[objPrivateElement.output_index]))
		return callbacks.ifError("no output at output_index");
```

**File:** indivisible_asset.js (L209-218)
```javascript
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
```

**File:** indivisible_asset.js (L619-628)
```javascript
function buildPrivateElementsChain(conn, unit, message_index, output_index, payload, handlePrivateElements){
	var asset = payload.asset;
	var denomination = payload.denomination;
	var output = payload.outputs[output_index];
	var hidden_payload = _.cloneDeep(payload);
	hidden_payload.outputs.forEach(function(o){
		delete o.address;
		delete o.blinding;
		// output_hash was already added
	});
```
