### Title
Single unattested recipient blocks payout to all other output addresses in a `spender_attested` asset payment - ([File: validation.js])

### Summary
When an asset is defined with `spender_attested: true`, `validatePaymentInputsAndOutputs` requires that **every** output address in the payment message be attested, not just the payer/authors. If a payment message pays multiple recipients at once (e.g. an AA merging several payout outputs into one payment message for the same asset), a single non-attested (or de-attested / "blacklisted"-equivalent) recipient causes the *entire* payment message — and therefore the entire unit — to fail validation, blocking payout to all the other, legitimate recipients in the same message. This mirrors the reported OpenQ/USDC issue where one blacklisted address in a token loop reverts the whole payout transaction.

### Finding Description
For assets with `spender_attested`, output-address attestation is enforced as an all-or-nothing check: [1](#0-0) 

This check operates on `arrOutputAddresses`, the full set of distinct addresses in the payment message's outputs, and fails the whole payment (`"some output addresses are not attested"`) if even one of them lacks attestation.

This is directly reachable from an Autonomous Agent (AA) response. AA-generated payment messages routinely combine multiple recipients into a single payment message per asset: [2](#0-1) 

The AA composer's own pre-flight check (`sendUnit`/`completePaymentPayload`) only loads asset info and validates issuer-side conditions such as `is_transferrable`, `cosigned_by_definer`, and whether authors are attested — it never checks that every output address is attested: [3](#0-2) 

Consequently, an AA can happily build and attempt to save a unit with several outputs for a `spender_attested` asset, and the failure is only detected later, in `writer.js`'s `validateAndSaveUnit` → `validation.js`'s `validatePaymentInputsAndOutputs`. When that validation fails, `aa_composer.js` bounces the entire trigger: [4](#0-3) 

A bounce reverts **all** the state changes and payouts computed for that trigger — not just the payment to the unattested address — denying payout to every other, legitimate, attested recipient who was supposed to receive funds in the same response.

### Impact Explanation
Any AA distributing a `spender_attested` asset (e.g., dividends, bounty payouts, batch distributions, futures/option settlements referenced in the oscript samples) to multiple recipients in a single message can be entirely blocked by a single recipient who is not (or is no longer) attested. This is analogous to the USDC-blacklist scenario: one "unauthorized" address in the batch causes the whole payout unit to be rejected, causing AA fund freezing / loss of the intended distribution to all other honest recipients, and forces the trigger into `bounce`, reverting state and refunding/losing the trigger sender's payment instead of completing the distribution. This satisfies the Medium-severity criteria for AA fund loss or freezing due to node disagreement/validation rejecting an otherwise-legitimate multi-recipient payout.

### Likelihood Explanation
Likelihood is Medium: it requires (a) an AA (or shared/multi-authored payment) that pays a `spender_attested` asset to more than one address in a single payment message, and (b) at least one of those addresses being unattested at validation time. Because AA output merging by asset (`mergeMessagesAndOutputs`) is standard behavior for AAs (combining several logical payouts of the same asset into one message), and attestor status can change between the trigger being composed/evaluated and the unit being validated (attestor lists can be updated via `asset_attestors` messages), this scenario is realistically triggerable by any unprivileged AA author distributing a `spender_attested` asset, or any user/AA sending such an asset to several addresses at once.

### Recommendation
- In `validatePaymentInputsAndOutputs` (validation.js), when `objAsset.spender_attested` is true, reject or filter out only the specific unattested outputs (e.g., treat the unit as invalid *before* it is built, or require the AA composer / wallet composer to pre-check attestation status of every output address and remove/split non-attested outputs before finalizing the message) rather than failing validation for the whole payment message.
- In `aa_composer.js`'s `completePaymentPayload`/`sendUnit`, proactively check `storage.filterAttestedAddresses` for every recipient of a `spender_attested` asset before completing the message, so that unattested recipients can be dropped (with an explicit bounce restricted to that portion, or logged/excluded) instead of allowing the whole trigger response to reach `validateAndSaveUnit` and bounce entirely.
- Alternatively, disallow merging multiple distinct recipients into a single payment message for `spender_attested` assets, so a failure due to one address's attestation status does not couple with and block payouts to other addresses.

### Proof of Concept
1. Definer creates asset `A` with `spender_attested: true` and an attestor list.
2. Deploy an AA that, upon trigger, sends asset `A` to two addresses, `X` (attested) and `Y` (not attested), in the same payment message — this is the normal pattern produced by `mergeMessagesAndOutputs` in `aa_composer.js` for multiple payment messages targeting the same asset.
3. Trigger the AA.
4. `sendUnit`/`completePaymentPayload` in `aa_composer.js` succeeds because it never verifies output-address attestation.
5. `validateAndSaveUnit` invokes `validation.js`'s `validatePaymentInputsAndOutputs`, which calls `storage.filterAttestedAddresses` on `[X, Y]`; since `Y` is not attested, `arrAttestedOutputAddresses.length !== arrOutputAddresses.length`, and the callback returns `"some output addresses are not attested"`.
6. `aa_composer.js`'s `bounce(err)` fires, reverting the AA response entirely — `X`, who should have received a legitimate payout, receives nothing, and the AA's intended state changes are lost, exactly mirroring the "one blacklisted recipient blocks payout for everyone" bug class from the original report.

### Citations

**File:** validation.js (L2630-2642)
```javascript
				async.series([
					function(cb){
						if (!objAsset.spender_attested)
							return cb();
						storage.filterAttestedAddresses(
							conn, objAsset, objValidationState.last_ball_mci, arrOutputAddresses, 
							function(arrAttestedOutputAddresses){
								if (arrAttestedOutputAddresses.length !== arrOutputAddresses.length)
									return cb("some output addresses are not attested");
								cb();
							}
						);
					},
```

**File:** aa_composer.js (L1010-1041)
```javascript
	function mergeMessagesAndOutputs(messages) {
		const arrMergedMessages = [];
		const assocMergedMessagesByAsset = Object.create(null);
		for (let message of messages) {
			if (message.app !== 'payment') {
				arrMergedMessages.push(message);
				continue;
			}
			const payload = message.payload;
			const asset = payload.asset || 'base';
			let objMergedMessage = assocMergedMessagesByAsset[asset];
			if (!objMergedMessage) {
				objMergedMessage = { app: 'payment', payload: { outputs: [] } };
				if (payload.asset)
					objMergedMessage.payload.asset = payload.asset;
				assocMergedMessagesByAsset[asset] = objMergedMessage;
				arrMergedMessages.push(objMergedMessage);
			}
			for (let output of payload.outputs) {
				if (output.amount === undefined) { // send-all output, don't merge with anything
					objMergedMessage.payload.outputs.push(output);
					continue;
				}
				const existing_output = objMergedMessage.payload.outputs.find(o => o.address === output.address && o.amount !== undefined);
				if (existing_output)
					existing_output.amount += output.amount;
				else
					objMergedMessage.payload.outputs.push(output);
			}
		}
		return arrMergedMessages;
	}
```

**File:** aa_composer.js (L1323-1344)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
					completePaymentPayload(payload, 0, function (err) {
						if (err)
							return cb(err);
						addOutputAddresses(payload.outputs);
						if (payload.outputs.length > 0) // send-all output might get removed while being the only output
							try {
								completeMessage(message);
							}
							catch (e) {
								return cb("completeMessage failed: " + e.toString());
							}
						cb();
					});
				});
```

**File:** aa_composer.js (L1405-1410)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
```
