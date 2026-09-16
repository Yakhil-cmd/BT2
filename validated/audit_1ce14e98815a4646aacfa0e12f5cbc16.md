### Title
Incorrect `output_hash` Committed in a Public Payment Message for Private Assets Permanently Freezes the Hidden Output - (File: validation.js)

### Summary
For private, fixed-denomination assets, the sender's wallet computes and publicly commits an `output_hash` (a hash of the still-secret `{address, blinding}` pair) inside an otherwise immutable DAG unit, while the actual private payload (address, blinding, amount) is delivered out-of-band later. As with `LineaRollup.submitData`, this is a "commit first, validate later" pattern: the public commitment is checked for basic shape only at submission time, but its correctness relative to the real private data is verified only later, and by then the commitment is permanently baked into the DAG and can never be changed.

### Finding Description
When composing a private indivisible-asset payment, the wallet generates `output_hash = getBase64Hash({address, blinding})` for each output and puts only the hash (not the address/blinding) into the payment message that gets hashed into and signed as part of the public unit: [1](#0-0) 

At unit-validation time (`validatePaymentInputsAndOutputs`), the network only checks that `output_hash` is present and correctly *shaped* (right length) for private fixed-denomination assets — it cannot check that the hash actually corresponds to any real, correctly-computed `{address, blinding}` pair, because that data isn't public: [2](#0-1) 

The real binding check happens much later, when the recipient (or hub, on light wallets) receives the private payload out-of-band and the chain is validated: [3](#0-2) 

If the `output_hash` committed in the immutable, already-stabilizing public unit does not match the hash of the actual `{address, blinding}` later delivered (e.g., because of a wallet/composer bug, a corrupted `blinding` value, or any mismatch between what was hashed and what is later revealed), `validatePrivatePayment` will permanently return `"output hash doesn't match"` for that output — for every future revalidation attempt, since the committed hash in the DAG can never be altered. This is exactly the class of bug described in the report: incorrect data is committed irreversibly before full validation, and later reconciliation (the private-payment "finalization" step) becomes permanently impossible because the earlier commitment cannot be revised, similar to how `submitData` locks in `shnarf`/state roots that `finalizeCompressedBlocksWithoutProof` later depends on.

Unlike a public payment (where address/amount are visible and checked immediately at unit-validation time), a private/hidden output_hash is accepted into the DAG on trust of its format alone, deferring the only real integrity check to a step that can never be retried successfully once the public commitment is wrong.

### Impact Explanation
If the `output_hash` committed on-chain is incorrect, the output it purports to encode becomes permanently unspendable and unverifiable: the recipient can never construct a private payload whose hash matches the committed value, so `validatePrivatePayment` will forever reject it, and the coins locked in that output can never be validated as spent/received. This is a fund-freezing condition tied to non-reversible on-chain commitments, analogous to the "impossible to finalize" state described for LineaRollup.

### Likelihood Explanation
This requires a bug or inconsistency in the sending wallet/composer when generating `output_hash` relative to the private payload it later reveals (e.g., composer/`indivisible_asset.js` composing logic diverging from the value later shared through `private_payloads`/private-chain messages). Given that hashing and blinding generation are handled by wallet code across multiple paths (`composer.js`, `indivisible_asset.js`, `wallet.js` signing-request validation) rather than a single canonical routine, a mismatch introduced by a bug or a modified/incompatible node implementation is plausible, mirroring the "operator/node implementation mistake" scenario in the original report.

### Recommendation
Move the full binding check earlier, or make it re-doable: e.g., require the private payload (or at least the pre-image data) to be provided together with unit validation for private fixed-denomination outputs so the hash mismatch is caught before the unit stabilizes, rather than only being discoverable when the recipient later tries to redeem it. Alternatively, provide an authenticated correction/cancellation mechanism analogous to allowing "alternate data" submission, so a wallet that detects it committed a wrong `output_hash` can issue a compensating transaction before the output is considered spendable by any counterparty.

### Proof of Concept
1. A wallet composes a private indivisible-asset payment and computes `output_hash = getBase64Hash({address, blinding})` for the recipient's output as in `indivisible_asset.js:780`.
2. Due to a bug (e.g., blinding generated inconsistently between the value hashed and the value later transmitted via `private_payloads`), the committed `output_hash` in the signed, broadcast unit does not correspond to the `{address, blinding}` pair that is later sent to the recipient.
3. The unit is validated and stabilizes on the DAG; `validatePaymentInputsAndOutputs` only confirms `output_hash` has the correct string length (`validation.js:2166-2167`), so the mismatched commitment is accepted permanently.
4. When the recipient later validates the private chain via `validatePrivatePayment`, `expected_output_hash !== our_hidden_output.output_hash` at `indivisible_asset.js:78-79` and the payment is rejected with `"output hash doesn't match"`.
5. Because the unit and its `output_hash` are immutable once broadcast/stabilized, there is no way to correct the commitment; the output can never be validated or spent, permanently freezing the funds it represents.

### Citations

**File:** indivisible_asset.js (L65-79)
```javascript
	var our_hidden_output = payload.outputs[objPrivateElement.output_index];
	if (!ValidationUtils.isNonemptyObject(payload.outputs[objPrivateElement.output_index]))
		return callbacks.ifError("no output at output_index");
	if (!ValidationUtils.isValidAddress(objPrivateElement.output.address))
		return callbacks.ifError("bad address in output");
	if (!ValidationUtils.isNonemptyString(objPrivateElement.output.blinding))
		return callbacks.ifError("bad blinding in output");
	try {
		var expected_output_hash = objectHash.getBase64Hash(objPrivateElement.output);
	}
	catch (e) {
		return callbacks.ifError("failed to calc output hash: " + e.message);
	}
	if (expected_output_hash !== our_hidden_output.output_hash)
		return callbacks.ifError("output hash doesn't match, output="+JSON.stringify(objPrivateElement.output)+", hash="+our_hidden_output.output_hash);
```

**File:** indivisible_asset.js (L778-787)
```javascript
							if (objAsset.is_private){
								payload.outputs.forEach(function(o){
									o.output_hash = objectHash.getBase64Hash({address: o.address, blinding: o.blinding});
								});
								var hidden_payload = _.cloneDeep(payload);
								hidden_payload.outputs.forEach(function(o){
									delete o.address;
									delete o.blinding;
								});
								payload_hash = objectHash.getBase64Hash(hidden_payload, bJsonBased);
```

**File:** validation.js (L2163-2177)
```javascript
		if (objAsset && objAsset.is_private){
			if (("output_hash" in output) !== !!objAsset.fixed_denominations)
				return callback("output_hash must be present with fixed denominations only");
			if ("output_hash" in output && !isStringOfLength(output.output_hash, constants.HASH_LENGTH))
				return callback("invalid output hash");
			if (!objAsset.fixed_denominations && !(("blinding" in output) && ("address" in output)))
				return callback("no blinding or address");
			if ("blinding" in output && !isStringOfLength(output.blinding, 16))
				return callback("bad blinding");
			if (("blinding" in output) !== ("address" in output))
				return callback("address and blinding must come together");
			if ("address" in output && !isValidAddressWithCase(output.address))
				return callback("output address " + JSON.stringify(output.address) + " invalid");
			if (output.address)
				count_open_outputs++;
```
