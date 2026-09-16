### Title
AAs silently drop payment messages for indivisible (fixed-denomination, "NFT-like") assets, permanently freezing deposited funds - ([File: aa_composer.js])

### Summary
In Obyte's Autonomous Agents (AAs), an oscript can define a `payment` message that pays out a `fixed_denominations` asset (Obyte's equivalent of an NFT/indivisible token) to a recipient. However, the AA response-composition logic in `aa_composer.js` silently strips any such payment message out of the response unit before it is ever built, so the asset is never actually transferred to the intended recipient, even though the AA's internal balance bookkeeping records it as being held by the AA.

### Finding Description
When an AA trigger fires and the oscript produces `messages` including a payment of a non-base asset, `sendUnit()` in `aa_composer.js` loads the asset info and explicitly defers/skips completing the payment payload for `fixed_denominations` assets: [1](#0-0) 

Immediately afterwards, any message paying a `fixed_denominations` asset is unconditionally filtered out of the set of messages that will make up the response unit: [2](#0-1) 

If that was the only outgoing message, the AA simply finishes with an empty/successful response ("no messages after removing fixed denominations") — no error is raised to the trigger sender or to the oscript author, and no funds move.

Meanwhile, deposits of `fixed_denominations` assets to an AA address *are* recorded as spendable AA balance: `insertAADefinitions()` and `updateFinalAABalances()` only exclude `is_private` assets from balance bookkeeping, not `fixed_denominations` ones: [3](#0-2) [4](#0-3) 

So the AA believes it holds a spendable balance of the indivisible asset, an oscript author can write logic to pay it out to a winner/claimant, but the actual unit-sending code path has no way to construct a valid indivisible-asset payment message (which requires special input/output/denomination handling as seen in `indivisible_asset.js` and the indivisible-specific validation in `validation.js`), so it just discards the message. There is no other code path anywhere in `aa_composer.js` that can spend a `fixed_denominations` output owned by an AA address, since AA addresses are not signed by any private key and the special composer logic used by wallets to build indivisible-asset transfers is never invoked for AA responses.

### Impact Explanation
Any AA designed to receive and redistribute indivisible assets — e.g. an escrow, marketplace, raffle, or collectible-reward AA — permanently and irrecoverably locks those assets at the AA address. Users who fund the AA expecting it to forward or pay out the asset to a winner/claimant will never see the funds delivered, and there is no protocol-level way to ever retrieve them afterward (unlike the original report where the NFT could at least be reclaimed via `refundDeposit`; here the coins are provably stuck forever, since AA addresses can't sign arbitrary transactions and the AA response-composition path unconditionally drops such messages). This is a clear case of AA fund loss/freezing reachable by any ordinary trigger sender or asset issuer.

### Likelihood Explanation
This is reachable by any unprivileged user: an asset issuer only needs to create a `fixed_denominations` asset (trivial, permissionless) and any AA author (or malicious AA author luring depositors) needs to write oscript logic intending to forward that asset. Once a user sends such an asset to the AA, either as part of a trigger or via a prior deposit, any AA response attempting to pay it onward is silently swallowed. No privileged role, malicious peer, or network condition is required — it is a straightforward, deterministic consequence of the AA response-building code.

### Recommendation
Either:
1. Reject/bounce triggers or AA definitions that involve `fixed_denominations` assets in AA payment outputs at validation time (e.g., in `aa_validation.js` output/asset validation) so AAs cannot be coded to (falsely) promise distribution of indivisible assets they can never actually send, or
2. Implement proper support in `aa_composer.js`'s `sendUnit()`/`completePaymentPayload()` for constructing valid indivisible-asset transfer inputs/outputs (denomination-aware, serial-number aware) so that such payment messages can actually be completed and sent, instead of being silently filtered at [5](#0-4) .

At minimum, when a payment message referencing a `fixed_denominations` asset is dropped, the AA should bounce with an explicit error rather than silently succeeding, so users and AA authors are alerted that the intended transfer never occurred instead of assets being silently frozen.

### Proof of Concept
1. Issue an asset with `fixed_denominations: true` and some `denominations` (an indivisible/NFT-like asset).
2. Deploy an AA whose oscript, upon receiving this asset from a depositor, is intended to later pay it out to a designated winner address via a `payment` message with `asset: <fixed_denom_asset>`.
3. Send the indivisible asset to the AA address. `insertAADefinitions`/`updateFinalAABalances` record the deposit in `aa_balances` for that asset [6](#0-5) .
4. Trigger the AA's payout logic. In `sendUnit()`, the payment message for the fixed-denomination asset is skipped from `completePaymentPayload` [7](#0-6)  and then filtered out of `messages` entirely [5](#0-4) .
5. The AA response unit is produced without any transfer of the indivisible asset (or an empty response if that was the only message), while `aa_balances` still shows the AA holding the asset — the winner never receives it, and no code path in the codebase can ever spend a fixed-denomination output from an AA address to release it.

### Citations

**File:** aa_composer.js (L543-586)
```javascript
	function updateFinalAABalances(arrConsumedOutputs, objUnit, cb) {
		if (trigger_opts.bAir)
			throw Error("updateFinalAABalances shouldn't be called with bAir");
		var assocDeltas = {};
		var arrNewAssets = [];
		arrConsumedOutputs.forEach(function (output) {
			if (!assocDeltas[output.asset])
				assocDeltas[output.asset] = 0;
			assocDeltas[output.asset] -= output.amount;
			// this might happen if there is another pending invocation of our AA that created the outputs we are spending now
			if (!objValidationState.assocBalances[address][output.asset])
				arrNewAssets.push(output.asset);
		});
		objUnit.messages.forEach(function (message) {
			if (message.app !== 'payment')
				return;
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address !== address)
					return;
				if (!assocDeltas[asset]) { // it can happen if the asset was issued by AA
					assocDeltas[asset] = 0;
					arrNewAssets.push(asset);
				}
				assocDeltas[asset] += output.amount;
			});
		});
		var arrQueries = [];
		if (arrNewAssets.length > 0) {
			var arrValues = arrNewAssets.map(function (asset) { return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", 0)"; });
			conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
		}
		for (var asset in assocDeltas) {
			if (assocDeltas[asset]) {
				conn.addQuery(arrQueries, "UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=?", [assocDeltas[asset], address, asset]);
				if (!objValidationState.assocBalances[address][asset])
					objValidationState.assocBalances[address][asset] = 0;
				objValidationState.assocBalances[address][asset] += assocDeltas[asset];
			}
		}
		if (assocDeltas.base)
			byte_balance += assocDeltas.base;
		async.series(arrQueries, cb);
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

**File:** aa_composer.js (L1350-1361)
```javascript
				messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
				if (messages.length === 0) {
					error_message = 'no messages after removing 0-outputs (2nd pass)';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
				messages = messages.filter(function (message) { return (message.app !== 'payment' || !message.payload.asset || !assetInfos[message.payload.asset].fixed_denominations); });
				if (messages.length === 0) {
					error_message = 'no messages after removing fixed denominations';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
```

**File:** storage.js (L953-961)
```javascript
					const params = bImmediatelyVisible ? [address, mci, unit] : [address, mci];
					conn.query(
						verb + " INTO aa_balances (address, asset, balance) \n\
						SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) AS balance \n\
						FROM outputs \n\
						CROSS JOIN units USING(unit) \n\
						LEFT JOIN assets ON asset=assets.unit \n\
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
						GROUP BY address, asset",
```
