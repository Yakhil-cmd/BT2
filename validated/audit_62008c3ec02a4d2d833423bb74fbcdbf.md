## Title
Out-of-bounds read / crash on malformed private-payment `output_index` field in `emitNewPrivatePaymentReceived` - (File: wallet.js)

### Summary
CVE-2017-9359 describes an OOB read/crash in PJSIP's multi-part body parser caused by insufficient validation of a crafted multi-part message before indexing into it. The analogous pattern in ocore is the handling of the "private payment chain" multi-part message (`body.chains` sent between paired wallet devices): the structural validation performed in `handlePrivatePaymentChains` does not check the `output`/`output_index` fields at all, yet a later stage (`emitNewPrivatePaymentReceived`) indexes into `payload.outputs` using an attacker-controlled `output_index` without a bounds check.

### Finding Description
`wallet.js`'s `handlePrivatePaymentChains` validates the shape of an incoming `body.chains` array from a paired device, but the check only requires `payload.inputs`/`payload.outputs` to be non-empty arrays of non-empty objects — it never validates the `output` or `output_index` fields of each chain element: [1](#0-0) 

After the chain is asset-validated and accepted (`ifOk`/`ifAccepted` → `checkIfAllValidated` → `emitNewPrivatePaymentReceived`), the wallet computes the received amount: [2](#0-1) 
```js
var output = objHeadPrivateElement.output;
if (output && output.address && arrAddresses.indexOf(output.address) >= 0){
    assocAmountsByAsset[asset] += payload.outputs[objHeadPrivateElement.output_index].amount;
    ...
}
```
This line dereferences `payload.outputs[objHeadPrivateElement.output_index]` without any bound check on `output_index`, and without verifying that `output_index` even makes sense for the asset type actually being transferred.

Whether the true `output_index` bound-check occurs earlier depends entirely on which asset-validation module processes the chain. `validateAndSavePrivatePaymentChain` (in `private_payment.js`) dispatches based on the **real, on-chain asset's** `fixed_denominations` flag, not on attacker-supplied payload fields: [3](#0-2) 

- For an **indivisible** asset, `indivisible_asset.js`'s `validatePrivatePayment` does bound-check `output_index` against `payload.outputs`: [4](#0-3) 
- For a **divisible** asset, `divisible_asset.js`'s `validateDivisiblePrivatePayment` never looks at `output`/`output_index` at all — it only validates `payload.inputs`/`payload.outputs` and spend proofs: [5](#0-4) 

Consequently, a paired device (an unprivileged private-payment counterparty) can send a private-payment chain for a **divisible** asset whose head element additionally carries a forged `output: {address: <victim_address>}` and an out-of-range `output_index` (e.g., `999`). Because divisible-asset validation ignores these extra fields entirely and `handlePrivatePaymentChains`'s structural check also ignores them, the malformed chain passes validation and reaches `emitNewPrivatePaymentReceived`, where `output` is truthy and `output.address` matches one of the victim's own addresses, forcing execution into the branch that reads `payload.outputs[999].amount` — `payload.outputs[999]` is `undefined`, so `.amount` throws an uncaught `TypeError`.

### Impact Explanation
This is a remotely triggerable crash of the recipient wallet process, invoked purely by delivering a crafted `private_payment_chain` (or `private_payloads`/textcoin file) message from a paired correspondent device or hub-forwarded message — no privileged access required. It matches the CVE's bug class (OOB read on a poorly bounds-checked field of a crafted multi-part payload leading to denial of service), mapped to the closest reachable ocore analog: crash of a node/wallet, preventing that wallet from processing further private payments (denial of service on receiving payments), rather than any state corruption.

### Likelihood Explanation
Any paired device or hub-relayed correspondent can send arbitrary `private_payment` chain bodies to a wallet; the divisible-asset code path deliberately omits `output`/`output_index` validation because they are conceptually irrelevant to divisible assets, but the shared post-validation notifier (`emitNewPrivatePaymentReceived`) still trusts them unconditionally whenever `output` is present. Triggering only requires that the attacker knows (or guesses/uses) one of the recipient's addresses as the `output.address`, which is realistic since addresses are often shared during payment negotiation.

### Recommendation
- Bound-check `objHeadPrivateElement.output_index` against `payload.outputs.length` before indexing in `emitNewPrivatePaymentReceived` (and any other place that reads `payload.outputs[output_index]` from an untrusted private element).
- Reject `output`/`output_index` fields on divisible-asset private elements during `handlePrivatePaymentChains`'s structural validation and/or during `validateDivisiblePrivatePayment`, since these fields are only meaningful for indivisible assets — use `hasFieldsExcept`-style strict schema validation consistent between the two asset-type code paths.
- Wrap the amount-accumulation logic in `emitNewPrivatePaymentReceived` in a try/catch (defensive) in addition to the schema fix, since this function runs after "successful" validation and any exception here is currently uncaught.

### Proof of Concept
1. Attacker (a paired device or a hub-relayed correspondent) crafts a private-payment chain for a real, on-chain **divisible** asset owned/known to be transferable to the victim.
2. The head chain element's `payload` contains valid-looking `inputs`/`outputs` arrays (satisfying `divisible_asset.js` validation) but the element itself additionally includes:
   ```json
   {
     "unit": "<valid unit>",
     "message_index": 0,
     "output_index": 999,
     "output": { "address": "<victim's real address>", "blinding": "..." },
     "payload": { "asset": "<divisible asset unit>", "inputs": [...], "outputs": [ /* 1-2 real outputs */ ] }
   }
   ```
3. Send this via the `private_payment_chain` justsaying to the victim's paired wallet (`wallet.js`'s `handlePrivatePaymentChains`).
4. `handlePrivatePaymentChains`'s schema check (`wallet.js:959-972`) does not inspect `output`/`output_index`, so the malformed chain passes.
5. `divisibleAsset.validateAndSavePrivatePaymentChain` validates the chain successfully (it never reads `output`/`output_index`).
6. On success, `checkIfAllValidated` → `emitNewPrivatePaymentReceived` executes; since `objHeadPrivateElement.output` is truthy and its address matches the victim, it evaluates `payload.outputs[999].amount`, throwing `TypeError: Cannot read properties of undefined (reading 'amount')`, crashing the event handling and terminating the wallet's processing of private payments (uncaught in this synchronous event emission).

**Uncertainty note:** I was not able to fully trace whether some outer `try/catch` in `mutex.lock`/`eventBus.emit` machinery would catch this specific exception and merely log it versus crash the whole process — the severity (soft failure vs hard crash) depends on Node's exception propagation through `eventBus.emit('maybe_new_transactions', ...)`/`emitNewPrivatePaymentReceived` call chain, which I could not fully confirm from the indexed context. At minimum this causes the private-payment-received notification/state update to break silently or throw, disrupting the wallet's transaction accounting for that chain.

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

**File:** private_payment.js (L104-105)
```javascript
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
```

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

**File:** divisible_asset.js (L78-179)
```javascript
function validateDivisiblePrivatePayment(conn, objPrivateElement, callbacks){
	
	var unit = objPrivateElement.unit;
	var message_index = objPrivateElement.message_index;
	var payload = objPrivateElement.payload;

	if (!ValidationUtils.isStringOfLength(payload.asset, constants.HASH_LENGTH))
		return callbacks.ifError("invalid asset in private divisible payment");
	if (!ValidationUtils.isNonemptyArray(payload.inputs))
		return callbacks.ifError("no inputs");
	
	validation.initPrivatePaymentValidationState(
		conn, unit, message_index, payload, callbacks.ifError, 
		function(bStable, objPartialUnit, objValidationState){
		
			var arrAuthorAddresses = objPartialUnit.authors.map(function(author) { return author.address; } );

			function validateSpendProofs(sp_cb){

				var arrSpendProofs = [];
				async.eachSeries(
					payload.inputs,
					function(input, cb){
						if (input.type === "issue"){
							var address = input.address || arrAuthorAddresses[0];
							try {
								var spend_proof = objectHash.getBase64Hash({
									asset: payload.asset,
									amount: input.amount,
									address: address,
									serial_number: input.serial_number
								});
							}
							catch (e) {
								return cb("failed to calc issue spend proof: " + e.message);
							}
							arrSpendProofs.push({address: address, spend_proof: spend_proof});
							cb();
						}
						else if (!input.type){
							conn.query(
								"SELECT address, amount, blinding FROM outputs WHERE unit=? AND message_index=? AND output_index=? AND asset=?",
								[input.unit, input.message_index, input.output_index, payload.asset],
								function(rows){
									if (rows.length !== 1)
										return cb("not 1 row when selecting src output");
									var src_output = rows[0];
									try {
										var spend_proof = objectHash.getBase64Hash({
											asset: payload.asset,
											unit: input.unit,
											message_index: input.message_index,
											output_index: input.output_index,
											address: src_output.address,
											amount: src_output.amount,
											blinding: src_output.blinding
										});
									}
									catch (e) {
										return cb("failed to calc transfer spend proof: " + e.message);
									}
									arrSpendProofs.push({address: src_output.address, spend_proof: spend_proof});
									cb();
								}
							);
						}
						else
							cb("unknown input type: "+input.type);
					},
					function(err){
						if (err)
							return sp_cb(err);
						//arrSpendProofs.sort(function(a,b){ return a.spend_proof.localeCompare(b.spend_proof); });
						conn.query(
							"SELECT address, spend_proof FROM spend_proofs WHERE unit=? AND message_index=? ORDER BY spend_proof_index", 
							[unit, message_index],
							function(rows){
								if (rows.length !== arrSpendProofs.length)
									return sp_cb("incorrect number of spend proofs");
								for (var i=0; i<rows.length; i++){
									if (rows[i].address !== arrSpendProofs[i].address || rows[i].spend_proof !== arrSpendProofs[i].spend_proof)
										return sp_cb("incorrect spend proof");
								}
								sp_cb();
							}
						);
					}
				);
			}

			var arrFuncs = [];
			arrFuncs.push(validateSpendProofs);
			arrFuncs.push(function(cb){
				validation.validatePayment(conn, payload, message_index, objPartialUnit, objValidationState, cb);
			});
			async.series(arrFuncs, function(err){
				console.log("162: "+err);
				err ? callbacks.ifError(err) : callbacks.ifOk(bStable, arrAuthorAddresses);
			});
		}
	);
}
```
