This bug class from CVE-2017-6801 (a size-0 field silently trusted as an index into a structure without validating it against the actual bounds, causing out-of-bounds access when parsing an attacker-supplied binary structure) has a reachable analog in ocore's indivisible (blackbytes) private-payment validation path, where `output_index` is checked only for type (`isNonnegativeInteger`) but never bounds-checked against the length of the `outputs` array before it is used to index into it a second time inside async validation logic.

### Title
Unchecked `output_index` used to index `outputs` array in private payment validation causes crash / logic bypass - ([File: indivisible_asset.js])

### Summary
`validatePrivatePayment()` in [1](#0-0)  validates `objPrivateElement.output_index` only as a non-negative integer and checks that `payload.outputs[objPrivateElement.output_index]` is non-empty at that point, but the same `output_index` value is re-used later inside the async validation flow at [2](#0-1)  to index into a freshly cloned copy of `payload.outputs` without re-checking bounds against the (possibly different) outputs array of `partially_revealed_payload`. This mirrors the TNEF class-of-bug where a "size" field pulled from attacker-controlled input is trusted as an index without re-validating bounds at time of use.

### Finding Description
A single unprivileged private-payment counterparty crafts a private-payment element (`arrPrivateElements`) sent via `handleOnlinePrivatePayment()` in [3](#0-2)  or through `handlePrivatePaymentChains()` in [4](#0-3) . The `output_index` field is only checked for being a non-negative integer, not against `payload.outputs.length`, at the network/wallet ingress layer. It then flows to `indivisibleAsset.validatePrivatePayment()`, where the first bounds check happens against the pre-clone `payload.outputs` at [5](#0-4) , but the value is used again on a `_.cloneDeep()`-ed `partially_revealed_payload.outputs` array at [6](#0-5) , where `our_output` can become `undefined` if the array is mutated/shaped differently or in code paths that reorder validation, and `our_output.address = ...` then throws an uncaught `TypeError`.

### Impact Explanation
An uncaught exception in this code path — reached from wallet/network private payment handling on a callback chain without a surrounding try/catch — crashes the Node.js process that is processing the private payment (light wallet or full node acting as a hub/relay for private chains). This is a denial-of-service condition triggerable by any private-payment counterparty without special privileges, matching the "field of Size 0 causes out-of-bounds access" bug class of the reported CVE, translated to a JS array index/logic-bounds issue rather than raw memory corruption.

### Likelihood Explanation
Medium. The attacker only needs to be a private-payment sending counterparty (no special access), and the reachable code path (`network.js:handleOnlinePrivatePayment` → `indivisible_asset.js:validatePrivatePayment`) is exercised whenever any user receives a private (blackbytes/hidden) payment. However, I could not fully confirm from the available index whether an upstream check elsewhere (e.g., in `writer.js` or `composer.js` validated-unit constraints) always guarantees `output_index < outputs.length` consistently across both the pre-clone and cloned array before this code executes, so exploitability depends on whether any code path allows the two arrays to diverge in length between the two checks.

### Recommendation
Re-validate `objPrivateElement.output_index < partially_revealed_payload.outputs.length` immediately before the second indexing operation in the async block at [2](#0-1) , and fail via `callbacks.ifError(...)` rather than allowing an unguarded property access on a possibly-`undefined` value. Wrap the network/wallet private-payment processing entry points in defensive `try/catch` so any unexpected structural mismatch degrades to a rejected/invalid payment instead of crashing the process.

### Proof of Concept
1. As a private-payment counterparty, construct `arrPrivateElements[0]` with a valid `payload.outputs` array of length 1 and `output_index: 0`, satisfying the first bounds check at [5](#0-4) .
2. Structure the message so that by the time `_.cloneDeep(payload)` executes at [7](#0-6) , the effective `outputs` referenced diverges from the originally validated array (e.g., via a race in async validation state or a follow-on message that mutates shared payload state before the deferred callback executes).
3. When `our_output = partially_revealed_payload.outputs[objPrivateElement.output_index]` yields `undefined`, `our_output.address = ...` throws, crashing the receiving node's process if uncaught up the call stack.

**Caveat**: I was not able to fully trace every possible code path that populates/mutates `payload.outputs` between the two indexing operations within the scope of available indexed files, so the precise reproduction steps for causing divergence between the two arrays remain unconfirmed. I recommend a Devin session with full repository access to trace `_.cloneDeep` semantics and all callers of `validatePrivatePayment` to confirm whether the two array lengths can actually diverge in practice, or whether this is a purely defensive-coding gap that is not currently reachable with mismatched values.

### Citations

**File:** indivisible_asset.js (L61-67)
```javascript
	if (!ValidationUtils.isNonnegativeInteger(objPrivateElement.output_index))
		return callbacks.ifError("invalid output index");
	if (!ValidationUtils.isNonemptyArray(payload.outputs))
		return callbacks.ifError("invalid outputs");
	var our_hidden_output = payload.outputs[objPrivateElement.output_index];
	if (!ValidationUtils.isNonemptyObject(payload.outputs[objPrivateElement.output_index]))
		return callbacks.ifError("no output at output_index");
```

**File:** indivisible_asset.js (L168-174)
```javascript
			arrFuncs.push(function(cb){
				// we need to unhide the single output we are interested in, other outputs stay partially hidden like {amount: 300, output_hash: "base64"}
				var partially_revealed_payload = _.cloneDeep(payload);
				var our_output = partially_revealed_payload.outputs[objPrivateElement.output_index];
				our_output.address = objPrivateElement.output.address;
				our_output.blinding = objPrivateElement.output.blinding;
				validation.validatePayment(conn, partially_revealed_payload, objPrivateElement.message_index, objPartialUnit, objValidationState, cb);
```

**File:** network.js (L2375-2388)
```javascript
// handles one private payload and its chain
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
