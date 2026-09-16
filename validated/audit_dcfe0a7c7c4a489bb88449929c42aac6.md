### Title
`spender_attested` asset validation fails an entire multi-recipient payment message if a single output address is not attested - ([File: validation.js])

### Summary
The USDC blacklisting report describes a class of bug where a single "denylisted" counterparty in a batched reward-distribution payment can cause the whole distribution to fail, freezing funds/rewards for every other, legitimate recipient in the same transaction. The ocore analog is the `spender_attested` asset condition, which is validated on the *entire set* of output addresses in a payment message rather than per-recipient, so one non-attested (i.e., "blacklisted"/de-whitelisted) address can block delivery to all co-batched recipients.

### Finding Description
When an asset is defined with `spender_attested: true`, every address receiving that asset must be on the current attestor list, similar in spirit to a KYC/whitelist (or its inverse, a blacklist) gate that USDC-style tokens implement off-chain. Validation of this rule happens once for the whole `arrOutputAddresses` array of a payment message: [1](#0-0) 

If any single output address in `arrOutputAddresses` is not attested, `storage.filterAttestedAddresses` returns a shorter list than the full address set, and the `cb("some output addresses are not attested")` branch rejects the *entire* payment message/unit — not just the output destined for the non-attested address: [2](#0-1) 

This condition is enforced globally at the payment-message level (`arrOutputAddresses`), which is populated by iterating over all outputs of the message during input/output validation (see the encompassing function `validatePaymentInputsAndOutputs`) rather than being checked and skipped per-output. Consequently, a payment message that batches many recipients (e.g., an AA distributing rewards to many stakers in one payment message for gas/complexity efficiency) will fail as a whole if even one recipient's attestation status changes (attestor list update via `asset_attestors`, expiry, or an attestor revoking the address) between message construction and validation.

An AA-authored reward distributor is a concrete unprivileged trigger path: any user can send a trigger unit that causes the AA to compose a payment message with outputs to multiple addresses for a `spender_attested` asset via `aa_composer.js`'s message-building/`completePaymentPayload` logic [3](#0-2) . If the resulting unit fails validation due to one non-attested output, the AA's `sendUnit`/`bounce` path is triggered [4](#0-3) , discarding the response unit and returning the AA to its bounce logic, which can eat the bounce fee and drop the intended state update/response entirely [5](#0-4) .

### Impact Explanation
- Any address that becomes de-attested (removed by an attestor, or was never attested) for a `spender_attested` asset can, by being included as one of the outputs in a shared/batched payment message, block delivery of that asset to *every other* recipient bundled in the same message.
- For AA-based reward/distribution logic that (for efficiency) batches multiple beneficiaries' payouts of a `spender_attested` asset into a single payment message, one blocked/unattested beneficiary causes the whole distribution attempt to bounce, freezing rewards for all other legitimate recipients in that batch and consuming AA response slots/bounce fees.
- This matches the reported class exactly: individual counterparty status (analogous to USDC blacklist) causes systemic disruption of a shared distribution mechanism rather than being isolated to the affected party.

### Likelihood Explanation
This requires an asset that uses `spender_attested: true` (a supported, documented asset feature) and any code path — AA or user wallet — that batches multiple recipients of that asset into a single payment message. Given `spender_attested` is a first-class asset attribute intentionally supported for compliance-style use cases, and batching multiple outputs of the same asset into one message is normal/expected behavior for efficiency (as seen in `aa_composer.js`'s payload construction), the precondition is realistic wherever a `spender_attested` asset is used for pooled or batched distributions.

### Recommendation
Validate `spender_attested` (and analogous conditions) per-output rather than requiring the full output set to pass together, or explicitly disallow/require that unions of unrelated recipients not be bundled into a single payment message for such assets. Alternatively, document/enforce that senders (including AA logic) must send `spender_attested` assets in one-output-per-message form so an attestation failure for one recipient cannot block payment to others, and expose the specific offending address in the validation error to aid automated retries that drop the bad output.

### Proof of Concept
Conceptual reproduction path (not directly executable from the indexed snippets, but derivable from the cited logic):
1. Define an asset with `spender_attested: true` and attestors A1.
2. A1 attests addresses X and Y.
3. Construct/compose a single payment unit for this asset with outputs to both X and Y (e.g., an AA reward-distribution response batching multiple stakers' payouts as in `aa_composer.js`).
4. Before the unit is validated/stabilized, A1 revokes attestation for Y (or Y was never attested).
5. Validation reaches `validatePaymentInputsAndOutputs` → `filterAttestedAddresses(conn, objAsset, last_ball_mci, [X, Y], ...)`, which returns only `[X]`; since `1 !== 2`, the whole unit is rejected with `"some output addresses are not attested"` [2](#0-1) , so X never receives its legitimate payment either.

### Citations

**File:** validation.js (L2630-2641)
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
```

**File:** aa_composer.js (L909-945)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
		if (bSecondary)
			return finish(null);
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
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

**File:** aa_composer.js (L1405-1411)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
```
