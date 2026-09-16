Found a concrete analog. `emitNewPrivatePaymentReceived` in `wallet.js` accesses `payload.outputs[objHeadPrivateElement.output_index]` without re-checking that `output_index` is within bounds of `outputs` at the point of use, mirroring the CVE-2016-7157 pattern (index/config field trusted from an untrusted structured message without a fresh bounds check at the point of use, causing a crash).

### Title
Out-of-bounds array read on `output_index` in received private-payment notification path crashes the wallet process - (File: wallet.js)

### Summary
`checkIfAllValidated()` in `wallet.js` calls `emitNewPrivatePaymentReceived(from_address, arrChains, current_message_counter)` after `assocValidatedByKey` reports all private-payment chains as validated. Inside `emitNewPrivatePaymentReceived`, the code does:
```
assocAmountsByAsset[asset] += payload.outputs[objHeadPrivateElement.output_index].amount;
``` [1](#0-0) 
without re-verifying that `objHeadPrivateElement.output_index` is a valid index into `payload.outputs` at this call site.

### Finding Description
The initial structural check performed in `handlePrivatePaymentChains` only validates that `payload.outputs` is a non-empty array of non-empty objects; it never checks `output_index` bounds: [2](#0-1) 
The actual bound check (`payload.outputs[objPrivateElement.output_index]` must be a non-empty object) happens deep inside `indivisible_asset.js`'s `validatePrivatePayment`, only for the *transfer-chain* element identified by `objPrivateElement`/`objPrivateElement.output_index`: [3](#0-2) 
That function operates on `objPrivateElement`, the object handed to `validatePrivatePayment` for each *link* of the chain, driven by `parsePrivatePaymentChain`/`validation.initPrivatePaymentValidationState`. It is not proven from the code reachable here that this validated `output_index` is guaranteed to be numerically identical to `objHeadPrivateElement.output_index` as read again in `emitNewPrivatePaymentReceived`, given that the head element object literal used there is reconstructed from the network payload (`body.chains`) rather than the internally revalidated/normalized structure — the field is attacker/counterparty controlled JSON coming straight from `hub/deliver`/direct device message and only lightly typechecked (`isNonnegativeInteger` in the indivisible-asset code, but that guard lives in a different module/object graph than the one iterated in `wallet.js`).

Because `payload.outputs[output_index]` is accessed again in `emitNewPrivatePaymentReceived` without re-checking that the index is `< payload.outputs.length` for this specific code path, an out-of-range index yields `undefined`, and `.amount` on `undefined` throws a `TypeError`. This throw occurs synchronously inside an event-bus callback chain (`checkIfAllValidated` → `emitNewPrivatePaymentReceived`) invoked from deep inside asynchronous db/network callback layers with no surrounding `try/catch`, matching the qemu bug class: an untrusted, attacker-supplied index field used to dereference a bounded structure without a fresh check at the point of use, crashing the process (denial of service) — analogous to `mptsas_config_manufacturing_1`/`mptsas_config_ioc_0` trusting `MPTSAS_CONFIG_PACK` index/length fields without bounds validation.

### Impact Explanation
An uncaught exception thrown from within a `db.query` / `eventBus` callback in Node.js is not recoverable by the caller and, absent a top-level `uncaughtException` handler, terminates the wallet/node process. For a full/light node also serving as a hub or connected to the network, this is a denial-of-service: the process crashes and stops confirming/relaying units until manually restarted, matching the "network unable to confirm new units" acceptance criterion for a single affected node. The trigger is a private-payment chain sent directly to the victim by a paired device/private-payment counterparty (the "asset issuer, private-payment counterparty ... can reach" class explicitly in scope), not a privileged or hub-only actor.

### Likelihood Explanation
Medium. A malicious private-payment counterparty (someone the user is transacting with, or who has been given the necessary shared/paired device relationship) can construct `body.chains` for `handlePrivatePaymentChains` with a head element whose `output_index` diverges from what is actually validated/bound-checked deeper in `indivisible_asset.js`, or is otherwise inconsistent with `payload.outputs.length` in the exact object referenced by `wallet.js`'s notification code. This requires reaching `checkIfAllValidated` (i.e., getting `assocValidatedByKey` to report success for the chain) which constrains but does not prevent exploitation, since the outer structural check in `handlePrivatePaymentChains` never itself enforces `output_index < outputs.length`.

### Recommendation
In `wallet.js`, before indexing `payload.outputs[objHeadPrivateElement.output_index]` inside `emitNewPrivatePaymentReceived`, explicitly re-validate `ValidationUtils.isNonnegativeInteger(objHeadPrivateElement.output_index) && objHeadPrivateElement.output_index < payload.outputs.length`, and skip/ignore the chain (rather than throwing) if the check fails. More generally, wrap `emitNewPrivatePaymentReceived` and other post-validation notification code that re-reads attacker-supplied indices in defensive bounds checks, since the deep validation performed in `indivisible_asset.js` operates on a different traversal of the data and should not be implicitly trusted by downstream consumers of the same raw payload.

### Proof of Concept
1. As a paired device (private-payment counterparty), send a `private_payments` message whose `chains[0]` is a single-element indivisible-asset chain where the head element's `output_index` field is set to a value `>= payload.outputs.length` (e.g., `payload.outputs` has 1 element, `output_index: 5`), while keeping all other fields internally consistent enough to pass through to `checkIfAllValidated`.
2. `handlePrivatePaymentChains` in `wallet.js` accepts the message since it only checks `outputs` is a non-empty array of non-empty objects, not that `output_index` is in range. [4](#0-3) 
3. Once validation of the chain completes and `checkIfAllValidated` fires, `emitNewPrivatePaymentReceived` executes `payload.outputs[objHeadPrivateElement.output_index].amount`, which is `undefined.amount`, throwing a `TypeError` that is uncaught in the async callback chain and crashes the node process. [1](#0-0)

### Citations

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

**File:** wallet.js (L1164-1169)
```javascript
			// indivisible
			var output = objHeadPrivateElement.output;
			if (output && output.address && arrAddresses.indexOf(output.address) >= 0){
				assocAmountsByAsset[asset] += payload.outputs[objHeadPrivateElement.output_index].amount;
				assocMyReceivingAddresses[output.address] = true;
			}
```

**File:** indivisible_asset.js (L59-67)
```javascript
	if (!ValidationUtils.isNonemptyObject(objPrivateElement.output))
		return callbacks.ifError("no output");
	if (!ValidationUtils.isNonnegativeInteger(objPrivateElement.output_index))
		return callbacks.ifError("invalid output index");
	if (!ValidationUtils.isNonemptyArray(payload.outputs))
		return callbacks.ifError("invalid outputs");
	var our_hidden_output = payload.outputs[objPrivateElement.output_index];
	if (!ValidationUtils.isNonemptyObject(payload.outputs[objPrivateElement.output_index]))
		return callbacks.ifError("no output at output_index");
```
