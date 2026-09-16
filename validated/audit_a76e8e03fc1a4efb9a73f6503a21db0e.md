### Title
Private-payment validation errors leak counterparty's own hidden output data (address/blinding) and asset details back over the network before being masked — inconsistent scrubbing compared to `wallet.js` — ([File: indivisible_asset.js])

### Summary
`indivisible_asset.js`'s `validatePrivatePayment()` builds error strings that embed the full contents of the private payment output object (address, blinding factor) via `JSON.stringify`, and separately logs the full spend-proof pre-image (asset, address, amount, blinding) via `console.log`. These raw error strings are propagated unmodified through `private_payment.js` → `network.js`'s `handleOnlinePrivatePayment`/`handleSavedPrivatePayments`, which call `sendResult(ws, {private_payment_in_unit: unit, result: 'error', error: error})`, sending the detailed error text back over the wire to the connected peer/hub. This mirrors the Argo CD GitOps Engine bug class: sensitive values embedded in validation-error text are not scrubbed before being surfaced to a party that should not necessarily see them in that form.

### Finding Description
In `indivisible_asset.js`, `validatePrivatePayment()`: [1](#0-0) 

constructs an error message with `JSON.stringify(objPrivateElement.output)` — the hidden output's `address` and `blinding` — whenever the recomputed `output_hash` doesn't match. The `blinding` factor is the secrecy-preserving nonce specific to Byteball/Obyte's private (indivisible) assets; it is deliberately withheld from third parties and only unhidden progressively down a private-payment chain.

Separately, the same function logs the complete spend-proof pre-image, including `asset`, `address`, `amount`, and `blinding`, unconditionally to the process console on every transfer-type validation: [2](#0-1) 

This error path is reached from network-facing entry points that relay a peer/hub-controlled `private_payment`/`private_payments` message through `validateAndSavePrivatePaymentChain` in `private_payment.js`: [3](#0-2) 

which for indivisible/fixed-denomination assets calls `indivisibleAsset.validateAndSavePrivatePaymentChain` → `validatePrivatePayment`, and whose `ifError` ultimately bubbles up to `network.js`: [4](#0-3) 

where the raw `error` string — potentially containing `JSON.stringify(objPrivateElement.output)` — is sent straight back to the originating peer with `sendResult(ws, {..., result: 'error', error: error})`.

Critically, `wallet.js`'s `handlePrivatePaymentChains()` already recognizes this exact bug class and explicitly masks it, replacing detailed validation errors with a generic `"an error"` string before returning to the hub: [5](#0-4) 

That comment ("do not leak error message to the hub") demonstrates the project's own awareness that private-payment validation errors must not be echoed verbatim to counterparties/hubs. However, the lower-level `network.js` handlers (`handleOnlinePrivatePayment` in the direct `private_payment` justsaying case, and `handleSavedPrivatePayments`) do not apply the same masking and forward the unscrubbed error text.

### Impact Explanation
Because a device/cosigner participating in a shared address or a chain relay can supply a crafted, slightly-invalid private element (e.g. altering `output.blinding` or triggering hash-mismatch branches) and receive back the exact JSON of `objPrivateElement.output` inside the error string, this can be used to confirm/extract blinding and address values that are supposed to remain confidential until explicitly unhidden in a private-payment chain (e.g. in multi-hop transfer or cosigner/shared-address scenarios where the object being validated does not fully belong to the requester, e.g. `objPrevPrivateElement.output`). This does not directly cause double-spend or fund loss, but it does violate the confidentiality guarantee of Obyte's private/indivisible-asset payments — the entire design goal of "private" assets is that amounts/blinding/ownership links stay hidden from parties other than the direct chain participants. Leaking blinding factors specifically undermines the unlinkability property since blinding is the secret that prevents third parties from correlating hidden outputs to revealed amounts/addresses.

### Likelihood Explanation
Exploitability requires only that an attacker be a normal, unprivileged participant able to send a `private_payment`/`private_payments` message to a peer/hub over an established wallet or network connection — no special privileges are required, matching this scan's "unprivileged unit poster / private-payment counterparty" reachability requirement. The relevant code path is directly reachable via the `private_payment` justsaying case in `network.js` and via `handlePrivatePaymentChains` in `wallet.js` (partially mitigated) as well as `handleSavedPrivatePayments`/`handleOnlinePrivatePayment` (not mitigated). Triggering the hash-mismatch or spend-proof-mismatch branch only requires crafting a malformed private element, which is low effort.

### Recommendation
Apply the same scrubbing pattern used in `wallet.js`'s `handlePrivatePaymentChains` (`cb("an error")`) uniformly across all network-facing private-payment error paths in `network.js` (`handleOnlinePrivatePayment`, `handleSavedPrivatePayments`, and the `private_payment` justsaying handler) so that only a generic error indicator is returned to the peer/hub, never the raw validation error string. Additionally, remove or gate behind a debug-only flag the `JSON.stringify(objPrivateElement.output)` embedding in the error message at `indivisible_asset.js:79`, and remove/guard the `console.log` at `indivisible_asset.js:125-133` that dumps the full spend-proof pre-image (including blinding factors) to logs.

### Proof of Concept
1. Attacker/device establishes a normal wallet connection to a hub/peer.
2. Attacker sends a `private_payment` (or `private_payments`) message containing a crafted `arrPrivateElements` where `objPrivateElement.output.blinding` (or `address`) is deliberately altered from the value implied by `payload.outputs[output_index].output_hash`.
3. `indivisible_asset.js`'s `validatePrivatePayment` computes `expected_output_hash` and finds a mismatch, calling `callbacks.ifError("output hash doesn't match, output=" + JSON.stringify(objPrivateElement.output) + ...)`.
4. This error propagates through `private_payment.js` → `network.js`'s `handleOnlinePrivatePayment`/`handleSavedPrivatePayments`, which call `sendResult(ws, {private_payment_in_unit: unit, result: 'error', error: error})`, returning the full JSON dump of `objPrivateElement.output` back to the sender/peer over the wire — unlike the equivalent `wallet.js` path, which intentionally replaces this with the generic `"an error"` string.

### Citations

**File:** indivisible_asset.js (L72-79)
```javascript
	try {
		var expected_output_hash = objectHash.getBase64Hash(objPrivateElement.output);
	}
	catch (e) {
		return callbacks.ifError("failed to calc output hash: " + e.message);
	}
	if (expected_output_hash !== our_hidden_output.output_hash)
		return callbacks.ifError("output hash doesn't match, output="+JSON.stringify(objPrivateElement.output)+", hash="+our_hidden_output.output_hash);
```

**File:** indivisible_asset.js (L125-133)
```javascript
				console.log("validation spend proof: "+JSON.stringify({
					asset: payload.asset,
					unit: input.unit,
					message_index: input.message_index,
					output_index: input.output_index,
					address: src_output.address,
					amount: prev_hidden_output.amount,
					blinding: src_output.blinding
				}));
```

**File:** private_payment.js (L23-44)
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
	
	var validateAndSave = function(){
		storage.readAsset(db, asset, null, function(err, objAsset){
			if (err)
				return callbacks.ifError(err);
			if (objAsset.is_private !== 1)
				return callbacks.ifError("asset is not private");
			if (!!objAsset.fixed_denominations !== !!headElement.payload.denomination)
				return callbacks.ifError("presence of denomination field doesn't match the asset type");
			if (!!objAsset.fixed_denominations !== ("output" in headElement))
				return callbacks.ifError("divisible asset must not have output field, indivisible must");
```

**File:** network.js (L2479-2497)
```javascript
						privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
							ifOk: function(){
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'accepted'});
								if (row.peer) // received directly from a peer, not through the hub
									eventBus.emit("new_direct_private_chains", [arrPrivateElements]);
								assocNewUnits[row.unit] = true;
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								console.log('emit '+key);
								eventBus.emit(key, true);
							},
							ifError: function(error){
								console.log("validation of priv: "+error);
							//	throw Error(error);
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: error});
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								eventBus.emit(key, false);
							},
```

**File:** wallet.js (L1035-1043)
```javascript
			network.handleOnlinePrivatePayment(ws, arrPrivateElements, true, {
				ifError: function(error){
					console.log("handleOnlinePrivatePayment error: "+error);
					cb("an error"); // do not leak error message to the hub
				},
				ifValidationError: function(unit, error){
					console.log("handleOnlinePrivatePayment validation error: "+error);
					cb("an error"); // do not leak error message to the hub
				},
```
