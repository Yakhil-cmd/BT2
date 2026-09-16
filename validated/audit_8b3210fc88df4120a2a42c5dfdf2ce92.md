### Title
Censorable Claiming of Private Payments Due to Required Counterparty Cooperation - ([File: indivisible_asset.js])

### Summary
Private (hidden-amount) payments in ocore commit only a `payload_hash` and `spend_proofs` on the public DAG; the actual `address`, `blinding`, and unhidden `amount` data needed to spend or even prove receipt of a private output are transmitted out-of-band, directly from the paying counterparty to the recipient/cosigners via `sendPrivatePayments`/`forwardPrivateChainsToDevices`. If the sending counterparty (or any prior link in the private chain) withholds this private element chain after the unit has been finalized on-chain, the recipient can never reconstruct the `spend_proof` or `output` needed to validate or later spend the funds — exactly the "requires operator/counterparty cooperation" pattern described in the report.

### Finding Description
When a private asset payment is composed, the payload (containing `address`, `blinding`, `amount` for every output) is deliberately hidden from the public unit: `payload_location` is set to `"none"` and only a hash-committing `payload_hash` plus `spend_proofs` are put on-chain, e.g. in `divisible_asset.js` composition (`objMessage.payload_hash = ...`, `objMessage.spend_proofs = ...`) and in `indivisible_asset.js` (`composeIndivisibleAssetPaymentJoint`, lines 791-802), where private outputs get `output_hash` fields on-chain but their real `address`/`blinding` never appear publicly: [1](#0-0) 

The recipient's copy of this hidden data is delivered solely via a direct device-to-device message (`"private_payments"`), built in `wallet_general.js`: [2](#0-1) 

To validate (and later spend) a received private output, the recipient must run `validatePrivatePayment`/`parsePrivatePaymentChain` in `indivisible_asset.js`, which requires the full, ordered chain of private elements back to issuance, including each ancestor's `output.address`/`output.blinding` (`objPrevPrivateElement.output.address`, `.blinding`) to recompute the `spend_proof` that is checked against what's already committed on-chain: [3](#0-2) [4](#0-3) 

The on-chain consensus layer (`validation.js validateMessage`) only checks that `spend_proofs` are well-formed hashes and not reused — it never verifies that the corresponding private data was actually delivered to anyone: [5](#0-4) 

Thus a unit spending/creating a private output can become fully valid and stable on the public DAG while the plaintext data needed to prove and further spend that output exists only in the paying counterparty's possession. `restorePrivateChains` can only reconstruct chains for a party that was itself the composer (using its own locally-generated blinding/addresses); a pure recipient with no local secret has no alternative path to rebuild the chain if the counterparty never sends (or partially sends) the `private_payments` message: [6](#0-5) 

This mirrors the reported L2→L1 issue: on-chain commitments (offsets/hashes) exist, but reconstructing usable proofs requires cooperation from a specific party (there, the L2 operator; here, the private-payment counterparty) who is not obligated by protocol to supply the necessary off-chain data, and whose non-cooperation is unverifiable and unpunishable at the validation layer.

### Impact Explanation
If a payer intentionally omits or corrupts the private element chain sent to a specific recipient (or any of several cosigner/change-address chains), that recipient's private funds become permanently unspendable/unprovable even though the unit is fully stable and valid consensus-wise. This is a direct "AA/asset fund loss or freezing" outcome for the affected party — the value is locked forever with no way for the victim to reconstruct the missing `address`/`blinding`/`amount` data from public information, since none of it is posted on the DAG for private assets.

### Likelihood Explanation
Any user composing a private payment (`composeIndivisibleAssetPaymentJoint`/`composeDivisibleAssetPaymentJoint`) is, by design, the sole source of the `private_payments` message to the recipient. No protocol-level enforcement or proof-of-delivery exists; a malicious or careless payer can simply omit sending the chain to one specific recipient among several outputs (e.g., withholding delivery to a disfavored cosigner/change address) while still finalizing the paying unit normally. This requires no special privilege beyond being a normal counterparty in a private transaction, matching the report's "single posted unit"-reachable actor model.

### Recommendation
- Consider requiring an on-chain, verifiable commitment sufficient for the recipient to independently reconstruct or dispute the required chain elements, or add a challenge/refund mechanism if the private payload is not delivered within a bounded time.
- At minimum, document and warn users/wallets that private payments carry a data-availability risk tied to counterparty cooperation, and provide tooling/heuristics to detect and flag payments whose chains were not fully delivered.
- Investigate protocol-level ways to bind delivery of `private_payments` data to finalization (e.g., requiring proof-of-receipt before treating the unit as complete from the wallet's perspective), reducing blind trust in the paying counterparty.

### Proof of Concept
1. Alice (payer) composes an indivisible private-asset payment to Bob using `composeAndSaveIndivisibleAssetPaymentJoint`, which builds `arrRecipientChains`/`arrCosignerChains` in the `preCommitCallback` of `getSavingCallbacks` and validates them locally with `validateAndSavePrivatePaymentChain` before broadcasting the unit — see `indivisible_asset.js` lines 869-919 and 619-716 for chain construction (`buildPrivateElementsChain`).
2. Alice broadcasts/finalizes the paying unit (only `payload_hash`/`spend_proofs`/`output_hash`s go public); the unit becomes valid and stable per `validation.js` (`validateMessage`, lines 1539-1582), with no on-chain check of chain-delivery.
3. Alice never calls (or deliberately fails to call) `sendPrivatePayments`/`forwardPrivateChainsToDevices` (`wallet_general.js` lines 18-40) to deliver the chain to Bob.
4. Bob has no other way to obtain his output's `address`/`blinding`/`amount`: `restorePrivateChains` (`indivisible_asset.js` lines 984-1061) only works for the party that composed the payment (using locally known secrets), not for a passive recipient.
5. Bob's funds, though fully finalized and stable on the DAG, can never be proven or spent — the private output is permanently frozen from Bob's perspective, with no available mechanism to challenge Alice's silence.

### Citations

**File:** indivisible_asset.js (L106-139)
```javascript
				var src_output = objPrevPrivateElement.output;
				var prev_hidden_output = objPrevPrivateElement.payload.outputs[input.output_index];
				if (!prev_hidden_output)
					return callbacks.ifError("no prev hidden output");
				input_address = src_output.address;
				try {
					spend_proof = objectHash.getBase64Hash({
						asset: payload.asset,
						unit: input.unit,
						message_index: input.message_index,
						output_index: input.output_index,
						address: src_output.address,
						amount: prev_hidden_output.amount,
						blinding: src_output.blinding
					});
				}
				catch (e) {
					return callbacks.ifError("failed to calc transfer spend proof: " + e.message);
				}
				console.log("validation spend proof: "+JSON.stringify({
					asset: payload.asset,
					unit: input.unit,
					message_index: input.message_index,
					output_index: input.output_index,
					address: src_output.address,
					amount: prev_hidden_output.amount,
					blinding: src_output.blinding
				}));
				arrFuncs.push(validateSourceOutput);
				objValidationState.src_coin = {
					src_output: src_output,
					denomination: payload.denomination,
					amount: prev_hidden_output.amount
				};
```

**File:** indivisible_asset.js (L187-228)
```javascript
function parsePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	var bAllStable = true;
	var issuePrivateElement = arrPrivateElements[arrPrivateElements.length-1];
	if (!issuePrivateElement.payload || !issuePrivateElement.payload.inputs || !issuePrivateElement.payload.inputs[0])
		return callbacks.ifError("invalid issue private element");
	var asset = issuePrivateElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in issue private element");
	var denomination = issuePrivateElement.payload.denomination;
	if (!denomination)
		return callbacks.ifError("no denomination in issue private element");
	async.forEachOfSeries(
		arrPrivateElements,
		function(objPrivateElement, i, cb){
			if (!objPrivateElement.payload || !objPrivateElement.payload.inputs || !objPrivateElement.payload.inputs[0])
				return cb("invalid payload");
			if (!objPrivateElement.output)
				return cb("no output in private element");
			if (objPrivateElement.payload.asset !== asset)
				return cb("private element has a different asset");
			if (objPrivateElement.payload.denomination !== denomination)
				return cb("private element has a different denomination");
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
			validatePrivatePayment(conn, objPrivateElement, prevElement, {
				ifError: cb,
				ifOk: function(bStable, input_address){
					objPrivateElement.bStable = bStable;
					objPrivateElement.input_address = input_address;
					if (!bStable)
						bAllStable = false;
					cb();
				}
			});
```

**File:** indivisible_asset.js (L778-802)
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
							}
							else
								payload_hash = objectHash.getBase64Hash(payload, bJsonBased);
							var objMessage = {
								app: "payment",
								payload_location: objAsset.is_private ? "none" : "inline",
								payload_hash: payload_hash
							};
							if (objAsset.is_private){
								assocPrivatePayloads[payload_hash] = payload;
								objMessage.spend_proofs = [arrPayloadsWithProofs[i].spend_proof];
							}
							else
								objMessage.payload = payload;
							arrMessages.push(objMessage);
```

**File:** indivisible_asset.js (L984-1061)
```javascript
function restorePrivateChains(asset, unit, to_address, handleChains){
	var arrRecipientChains = [];
	var arrCosignerChains = [];
	db.query(
		"SELECT DISTINCT message_index, denomination, payload_hash, version \n\
		FROM outputs JOIN messages USING(unit, message_index) CROSS JOIN units USING(unit) WHERE unit=? AND asset=?", 
		[unit, asset], 
		function(rows){
			async.eachSeries(
				rows,
				function(row, cb){
					var payload = {asset: asset, denomination: row.denomination};
					var message_index = row.message_index;
					db.query(
						"SELECT src_unit, src_message_index, src_output_index, denomination, asset FROM inputs WHERE unit=? AND message_index=?", 
						[unit, message_index],
						function(input_rows){
							if (input_rows.length !== 1)
								throw Error("not 1 input");
							var input_row = input_rows[0];
							if (input_row.asset !== asset)
								throw Error("assets don't match");
							if (input_row.denomination !== row.denomination)
								throw Error("denominations don't match");
							if (input_row.src_message_index === null || input_row.src_output_index === null)
								throw Error("only transfers supported");
							var input = {
								unit: input_row.src_unit,
								message_index: input_row.src_message_index,
								output_index: input_row.src_output_index
							};
							payload.inputs = [input];
							db.query(
								"SELECT address, amount, blinding, output_hash FROM outputs \n\
								WHERE unit=? AND asset=? AND message_index=? ORDER BY output_index", 
								[unit, asset, message_index],
								function(outputs){
									if (outputs.length === 0)
										throw Error("outputs not found for mi "+message_index);
									if (!outputs.some(function(output){ return (output.address && output.blinding); }))
										throw Error("all outputs are hidden");
									payload.outputs = outputs;
									var hidden_payload = _.cloneDeep(payload);
									hidden_payload.outputs.forEach(function(o){
										delete o.address;
										delete o.blinding;
									});
									var payload_hash = objectHash.getBase64Hash(hidden_payload, row.version !== constants.versionWithoutTimestamp);
									if (payload_hash !== row.payload_hash)
										throw Error("wrong payload hash");
									async.forEachOfSeries(
										payload.outputs,
										function(output, output_index, cb3){
											if (!output.address || !output.blinding) // skip
												return cb3();
											// we have only heads of the chains so far. Now add the tails.
											buildPrivateElementsChain(
												db, unit, message_index, output_index, payload, 
												function(arrPrivateElements){
													if (output.address === to_address)
														arrRecipientChains.push(arrPrivateElements);
													arrCosignerChains.push(arrPrivateElements);
													cb3();
												}
											);
										},
										cb
									);
								}
							);
						}
					);
				},
				function(){
					handleChains(arrRecipientChains, arrCosignerChains);
				}
			);
		}
```

**File:** wallet_general.js (L18-28)
```javascript
// unlike similar function in network, this function sends multiple chains in a single package
function sendPrivatePayments(device_address, arrChains, bForwarded, conn, onSaved){
	var body = {chains: arrChains};
	if (bForwarded)
		body.forwarded = true;
	device.sendMessageToDevice(device_address, "private_payments", body, {
		ifOk: function(){},
		ifError: function(){},
		onSaved: onSaved
	}, conn);
}
```

**File:** validation.js (L1539-1582)
```javascript
	if ("spend_proofs" in objMessage){
		if (objValidationState.bAA)
			return callback("spend proofs in AA");
		if (objMessage.app !== "payment")
			return callback("spend proofs in non-payment message");
		if (objMessage.payload_location !== "none")
			return callback("spend proofs in message with payload");
		if (!Array.isArray(objMessage.spend_proofs) || objMessage.spend_proofs.length === 0 || objMessage.spend_proofs.length > constants.MAX_SPEND_PROOFS_PER_MESSAGE)
			return callback("spend_proofs must be non-empty array max "+constants.MAX_SPEND_PROOFS_PER_MESSAGE+" elements");
		var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
		// spend proofs are sorted in the same order as their corresponding inputs
		//var prev_spend_proof = "";
		for (var i=0; i<objMessage.spend_proofs.length; i++){
			var objSpendProof = objMessage.spend_proofs[i];
			if (typeof objSpendProof !== "object")
				return callback("spend_proof must be object");
			if (hasFieldsExcept(objSpendProof, ["spend_proof", "address"]))
				return callback("unknown fields in spend_proof");
			//if (objSpendProof.spend_proof <= prev_spend_proof)
			//    return callback("spend_proofs not sorted");
			
			if (!isValidBase64(objSpendProof.spend_proof, constants.HASH_LENGTH))
				return callback("spend proof " + JSON.stringify(objSpendProof.spend_proof) + " is not a valid base64");
			
			var address = null;
			if (arrAuthorAddresses.length === 1){
				if ("address" in objSpendProof)
					return callback("when single-authored, must not put address in spend proof");
				address = arrAuthorAddresses[0];
			}
			else{
				if (typeof objSpendProof.address !== "string")
					return callback("when multi-authored, must put address in spend_proofs");
				if (arrAuthorAddresses.indexOf(objSpendProof.address) === -1)
					return callback("spend proof address "+objSpendProof.address+" is not an author");
				address = objSpendProof.address;
			}
			
			if (objValidationState.arrInputKeys.indexOf(objSpendProof.spend_proof) >= 0)
				return callback("spend proof "+objSpendProof.spend_proof+" already used");
			objValidationState.arrInputKeys.push(objSpendProof.spend_proof);
			
			//prev_spend_proof = objSpendProof.spend_proof;
		}
```
