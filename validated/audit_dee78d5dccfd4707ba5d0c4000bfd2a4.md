This confirms the analog: `aa_composer.js` line 1329 explicitly acknowledges that if an AA's own code tries to send out a private asset, "it'll fail validation anyway due to lack of spend_proofs," and returns `cb("sending private asset from AA")`. This shows AAs structurally cannot originate spends of private assets because they lack the blinding/spend-proof material private payments require [1](#0-0) . However, there is no symmetric protection on the *receiving* side: nothing stops a normal user (unaware that a base32 address is actually an AA) from sending a private asset payment to that address as an ordinary counterparty. The address format for an AA is indistinguishable from a regular single/multi-sig payment address, so the sender's intent ("pay a private asset to this address, expecting the counterparty to later spend or forward it like a normal wallet") is silently defeated at the recipient side, exactly mirroring the `sendEth` bug where the sender's explicit expectation of a payment form is overridden invisibly based on what kind of account actually holds the address.

### Title
Private-asset payments to AA addresses become permanently unspendable, mirroring hidden recipient-type override that silently defeats sender intent - (File: aa_composer.js)

### Summary
An unprivileged wallet user who sends a private-asset payment (e.g. a private token) to a Base32 address that looks like an ordinary payment address can be paying into an Autonomous Agent (AA) without any way to know it. ocore's own code documents that AAs "fail validation anyway due to lack of spend_proofs" when they try to send out a private asset [2](#0-1) , but this constraint only guards outgoing AA sends — nothing prevents or warns the sender when private-asset *inputs* are sent to an AA address as a normal counterparty payment. Because AA addresses are visually and structurally identical to regular addresses, the same "recipient's true nature silently changes the outcome of an explicit payment" pattern described in the original `removeLiquidity`/`sendEth` report is reproduced: the sender explicitly composes a private payment expecting the normal counterparty flow (private element chain forwarded, later spendable by that counterparty), but if the address is actually an AA, the funds become permanently stuck.

### Finding Description
Private assets in ocore are not spendable purely from on-chain data: spending requires the `spend_proof` and blinding factors of the specific output, which are transmitted peer-to-peer through the "private chain" mechanism between wallet devices (`wallet.js` `forwardPrivateChainsToOtherMembersOfOutputAddresses`/`sendPrivatePayments` machinery) [3](#0-2) . AAs do not participate in this private communication channel at all — they have no device, no correspondent connection, and no mechanism to receive or store the private payload/blinding data out of band.

Separately, `aa_composer.js`'s own trigger-response logic explicitly acknowledges that an AA can never spend a private asset it holds, aborting with `"sending private asset from AA"` because the transaction would fail validation for lack of `spend_proofs` [1](#0-0) .

Despite this documented one-way limitation, there is no corresponding check anywhere in `validation.js`'s `validatePayment`/`validatePaymentInputsAndOutputs` [4](#0-3)  or in `aa_addresses.js`'s `checkAAOutputs` [5](#0-4)  that rejects, warns about, or bounces a private-asset payment whose output address belongs to a known AA. `checkAAOutputs` only checks that bounce fees are covered for base/asset amounts sent to an AA; it has no special-casing for `is_private` assets, and is only invoked from the wallet's own `sendMultiPayment` path as a convenience check, not as a protocol-level constraint [6](#0-5) . A hand-crafted unit (or a wallet build that skips this convenience check) can still post a valid private payment to an AA address.

Because a Base32 address gives no visual indication of whether it is a normal wallet, shared address, or an AA, the sender has no way to know — at the moment they commit to sending a private payment — that the recipient cannot ever spend the funds. This exactly parallels the original bug class: an explicit, user-controlled payment intent ("pay this private asset to this counterparty, who will later spend/forward it normally") is silently overridden by a hidden property of the recipient (being an AA rather than a normal wallet), leading to funds that are technically credited on-chain but functionally frozen forever.

### Impact Explanation
Funds sent as a private asset to an AA address are permanently locked: the AA cannot spend them (guarded explicitly in `aa_composer.js`), and the counterparty who could theoretically spend them (if the AA operator somehow got the private elements) has no protocol pathway to receive the spend-proof/blinding data, since AAs are not addressable via the device-to-device private-chain forwarding mechanism used for all other private transfers. This is a concrete, unrecoverable loss of user funds triggered entirely by an unprivileged private-payment counterparty's own action, with no attacker required — matching the "AA fund loss or freezing" and "unauthorized/irrecoverable loss" criteria.

### Likelihood Explanation
Likelihood is realistic but not high-frequency: it requires a user to send a private asset (not the common case of base bytes) to an address they have not verified is a plain wallet address. Since AA addresses are indistinguishable from normal addresses to end users and to most wallet UIs, and private-asset ecosystems (private tokens) are a supported first-class ocore feature, this can occur through simple user error, a malicious AA operator advertising an address to receive "private" payments, or third-party integration code that doesn't specifically special-case AA addresses before initiating a private transfer.

### Recommendation
Add an explicit guard, analogous to the outgoing-side check in `aa_composer.js` line 1329, on the incoming/validation side: in `validatePayment`/`validatePaymentInputsAndOutputs` (or in `checkAAOutputs`), detect when a private-asset (`is_private`) payment output address is a registered AA address and reject the unit (or at minimum have `checkAAOutputs` surface a hard error rather than only checking bounce-fee sufficiency) so wallets cannot compose or broadcast such payments. This closes the asymmetry where AAs are protected from failing when *sending* private assets but users are not protected from irrecoverably losing funds when *receiving*-side logic silently can't support them.

### Proof of Concept
1. Deploy any AA (its Base32 address is computed the same way as a normal address, via `objectHash.getChash160` on its definition, and is indistinguishable from a plain address to a payer).
2. Issue or acquire a private asset (`is_private: true`) in a wallet.
3. Use `sendMultiPayment` (or hand-craft a unit) to send that private asset to the AA's address, bypassing/absent the wallet's own `checkAAOutputs` convenience check (which does not special-case `is_private` assets) [5](#0-4) .
4. The payment message validates successfully via `validatePayment`/`validatePaymentInputsAndOutputs` since no code path there rejects private payments to AA addresses [4](#0-3) .
5. The output is now owned by the AA. Confirm that the AA can never spend it: any attempt by the AA to include this asset in a response payment hits the `"sending private asset from AA"` guard in `aa_composer.js` [2](#0-1) , and no correspondent device exists for the AA to receive the private spend-proof/blinding data needed by any other party to spend it either — the funds are permanently frozen.

### Citations

**File:** aa_composer.js (L1323-1330)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```

**File:** wallet.js (L2186-2194)
```javascript
	if (!opts.aa_addresses_checked) {
		aa_addresses.checkAAOutputs(arrPayments, function (err) {
			if (err)
				return handleResult(err);
			opts.aa_addresses_checked = true;
			sendMultiPayment(opts, handleResult);
		});
		return;
	}
```

**File:** wallet.js (L2405-2429)
```javascript
							var sendToRecipients = function(cb2){
								if (recipient_device_address) {
									walletGeneral.sendPrivatePayments(recipient_device_address, arrChainsOfRecipientPrivateElements, false, conn, cb2);
								} 
								else if (Object.keys(assocAddresses).length > 0) {
									var mnemonic = assocMnemonics[Object.keys(assocMnemonics)[0]]; // TODO: assuming only one textcoin here
									if (typeof opts.getPrivateAssetPayloadSavePath === "function") {
										opts.getPrivateAssetPayloadSavePath(function(fullPath, cordovaPathObj){
											if (!fullPath && (!cordovaPathObj || !cordovaPathObj.fileName)) {
												return cb2("no file path provided for storing private payload");
											}
											storePrivateAssetPayload(fullPath, cordovaPathObj, mnemonic, arrChainsOfRecipientPrivateElements, function(err) {
												if (err)
													throw Error(err);
												saveMnemonicsPreCommit(conn, objJoint, cb2);
											});
										});
									} else {
										throw Error("no getPrivateAssetPayloadSavePath provided");
									}
								}
								else { // paying to another wallet on the same device
									forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChainsOfRecipientPrivateElements, false, conn, cb2);
								}
							};
```

**File:** validation.js (L2060-2125)
```javascript
function validatePayment(conn, payload, message_index, objUnit, objValidationState, callback){

	if (!isNonemptyObject(payload))
		return callback("payment must be a non-empty object");
	if (!isNonemptyArray(payload.inputs))
		return callback("no inputs");
	if (!isNonemptyArray(payload.outputs))
		return callback("no outputs");

	if (!("asset" in payload)){ // base currency
		if (hasFieldsExcept(payload, ["inputs", "outputs"]))
			return callback("unknown fields in payment message");
		if (objValidationState.bHasBasePayment)
			return callback("can have only one base payment");
		objValidationState.bHasBasePayment = true;
		return validatePaymentInputsAndOutputs(conn, payload, null, message_index, objUnit, objValidationState, callback);
	}
	
	// asset
	if (!isStringOfLength(payload.asset, constants.HASH_LENGTH))
		return callback("invalid asset");
	
	var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
	// note that light clients cannot check attestations
	storage.loadAssetWithListOfAttestedAuthors(conn, payload.asset, objValidationState.last_ball_mci, arrAuthorAddresses, objValidationState.bAA, function(err, objAsset){
		if (err)
			return callback(err);
		if (hasFieldsExcept(payload, ["inputs", "outputs", "asset", "denomination"]))
			return callback("unknown fields in payment message");
		if (objAsset.fixed_denominations){
			if (!isPositiveInteger(payload.denomination))
				return callback("no denomination");
		}
		else{
			if ("denomination" in payload)
				return callback("denomination in arbitrary-amounts asset")
		}
		if (!!objAsset.is_private !== !!objValidationState.bPrivate)
			return callback("asset privacy mismatch");
		var bIssue = (payload.inputs[0].type === "issue");
		var issuer_address;
		if (bIssue){
			if (arrAuthorAddresses.length === 1)
				issuer_address = arrAuthorAddresses[0];
			else{
				issuer_address = payload.inputs[0].address;
				if (arrAuthorAddresses.indexOf(issuer_address) === -1)
					return callback("issuer not among authors");
			}
			if (objAsset.issued_by_definer_only && issuer_address !== objAsset.definer_address)
				return callback("only definer can issue this asset");
		}
		if (objAsset.cosigned_by_definer && arrAuthorAddresses.indexOf(objAsset.definer_address) === -1)
			return callback("must be cosigned by definer");
		
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
		}
		validatePaymentInputsAndOutputs(conn, payload, objAsset, message_index, objUnit, objValidationState, callback);
	});
}
```

**File:** aa_addresses.js (L120-156)
```javascript
function checkAAOutputs(arrPayments, handleResult) {
	var assocAmounts = {};
	arrPayments.forEach(function (payment) {
		var asset = payment.asset || 'base';
		payment.outputs.forEach(function (output) {
			if (!assocAmounts[output.address])
				assocAmounts[output.address] = {};
			if (!assocAmounts[output.address][asset])
				assocAmounts[output.address][asset] = 0;
			assocAmounts[output.address][asset] += output.amount;
		});
	});
	var arrAddresses = Object.keys(assocAmounts);
	readAADefinitions(arrAddresses, function (err, rows) {
		if (err)
			return handleResult(err);
		if (rows.length === 0)
			return handleResult();
		var arrMissingBounceFees = [];
		rows.forEach(function (row) {
			var arrDefinition = JSON.parse(row.definition);
			var bounce_fees = arrDefinition[1].bounce_fees;
			if (!bounce_fees)
				bounce_fees = { base: constants.MIN_BYTES_BOUNCE_FEE };
			if (!bounce_fees.base)
				bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
			for (var asset in bounce_fees) {
				var amount = assocAmounts[row.address][asset] || 0;
				if (amount < bounce_fees[asset])
					arrMissingBounceFees.push({ address: row.address, asset: asset, missing_amount: bounce_fees[asset] - amount, recommended_amount: bounce_fees[asset] });
			}
		});
		if (arrMissingBounceFees.length === 0)
			return handleResult();
		handleResult(new MissingBounceFeesErrorMessage({ error: "The amounts are less than bounce fees", missing_bounce_fees: arrMissingBounceFees }));
	});
}
```
