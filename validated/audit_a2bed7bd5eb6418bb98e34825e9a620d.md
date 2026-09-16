### Title
Sending a private asset to an AA address causes an irrecoverable, permanent freeze of funds - (File: aa_composer.js)

### Summary
This is a valid analog of the [H-04] `recoverERC721` bug. In both cases, a value transfer sends an asset into an address whose logic can never move that asset back out: in the C4 report, `RdpxV2Core` receives NFTs it structurally has no code path to transfer; in `ocore`, an AA address can receive a private asset payment (from any unprivileged sender) that the AA's own trigger-handling logic is structurally forbidden from ever spending, because AAs cannot produce the `spend_proofs`/hidden-output chain that private payments require.

### Finding Description
`checkAAOutputs` in `aa_addresses.js` only checks that a payment to an AA address covers the `bounce_fees` in the given asset; it never inspects whether the asset `is_private`, so any wallet, AA-trigger sender, or asset issuer can freely direct a private-asset payment to an AA's address. [1](#0-0) 

Once such an output lands on an AA address, `aa_composer.js`'s trigger-handling code explicitly forbids the AA from ever including that asset in an outgoing payment message: when composing the AA's response, if the asset being sent `is_private`, the message is rejected outright with `"sending private asset from AA"`, with the comment confirming this would fail validation anyway "due to lack of spend_proofs". [2](#0-1) 

This is not a transient/soft restriction — private payments require constructing a chain of hidden outputs with `spend_proofs` derived from private, off-chain data that only human/wallet actors can produce and forward peer-to-peer (see `indivisible_asset.js`/`divisible_asset.js`/`private_payment.js` private-payment machinery). AAs execute deterministic formula logic on-chain and have no mechanism to generate, store, or forward such private spend proofs, and `validation.js` explicitly disallows `spend_proofs` in AA-authored units (`if (objValidationState.bAA) return callback("spend proofs in AA")`), corroborating that AAs can never spend a private asset regardless of what the AA script tries to do. Consequently, no AA definition or subsequent AA logic upgrade can ever unlock these funds — this mirrors the ERC721 case where `RdpxV2Core`'s fixed code (inherited from `ERC721Holder`, `AccessControl`, etc.) has no path to move the received NFT.

### Impact Explanation
Any unprivileged party (a trigger sender, or even the AA operator/owner testing their own AA, or a well-meaning user paying an AA in a private token) who sends a private-asset payment to any AA address permanently and irrecoverably loses that value: it cannot be spent, forwarded, refunded, or bounced back by the AA, since the AA can never construct a compliant private-payment message to release it. This constitutes concrete AA fund loss/freezing at the protocol level, not merely an application-specific AA-script oversight — it is caused by a structural limitation of `ocore`'s AA engine that is not proactively prevented for the sender.

### Likelihood Explanation
Likelihood is non-trivial: any regular wallet payment to an asset that happens to be `is_private` can be misdirected to an AA address (accidentally or by a malicious counterparty crafting a private asset and enticing/instructing users to pay an AA with it), and there is no explicit guard rejecting such destinations the way `checkAAOutputs` does for insufficient bounce fees. Given AAs are commonly used as public-facing payment endpoints (DEXes, faucets, bots), the risk of a user paying with a private asset by mistake (or of an attacker constructing a private asset intentionally to trap a target AA's funds) is realistic.

### Recommendation
Add an explicit protocol-level or wallet-level guard analogous to the existing `checkAAOutputs` bounce-fee check that rejects (or at minimum strongly warns on) payments of `is_private` assets to AA addresses before they are broadcast, since these funds are structurally unrecoverable by the AA. Alternatively, disallow private-asset outputs to `aa_addresses` in `validatePayment`/`validatePaymentInputsAndOutputs` so that such units fail consensus-level validation rather than silently succeeding and stranding value.

### Proof of Concept
1. Define an asset with `is_private: true`, `fixed_denominations: true` (a valid private, indivisible asset per `validateAssetDefinition` rules in `validation.js`).
2. Post a private payment (with proper `spend_proofs`/hidden outputs per `indivisible_asset.js`) whose output address is any deployed AA address.
3. The payment validates and stabilizes normally (private assets pay to any valid address; there is no AA-specific restriction in `validatePaymentInputsAndOutputs`).
4. Trigger the AA (or wait for its next execution) and have its script attempt to forward or refund that asset in a `payment` message — `aa_composer.js` rejects the message with `"sending private asset from AA"` [3](#0-2) , and no alternate `execute`-like path exists for AAs to release private-asset value.
5. The private asset value received by the AA address remains permanently unspendable — irrecoverable loss for whoever sent it, and impossible to fix even by publishing a corrected/base AA, since the underlying limitation is structural to how `ocore` computes private-payment spend proofs, not to the specific AA's script.

### Citations

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
