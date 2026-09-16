### Title
Griefing an Autonomous Agent's asset payments via unfiltered dust outputs of non-base assets - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `readStableOutputs`/`readUnstableOutputsSentByAAs` helpers, used when an AA composes a `payment` message in `sendUnit`, apply a dust-filter (`amount>=FULL_TRANSFER_INPUT_SIZE`) only to **base-asset** outputs. Any custom-asset output sent to the AA's address, regardless of how tiny, is eligible to be picked up as an input. Combined with the fact that AA-authored units are exempt from `MAX_INPUTS_PER_PAYMENT_MESSAGE` and the `MAX_UNIT_LENGTH` checks in `validation.js`, an unprivileged attacker can flood an AA's address with a large number of minuscule-amount outputs of an asset the AA is known to pay out in, forcing every subsequent legitimate AA payment in that asset to consume all of these dust inputs. This inflates the AA's response unit size/fees (paid in bytes from the AA's own balance) and can bounce or drain the AA, exactly the “fill a shared, unlimited/whitelist-bypassing structure with worthless value to block a legitimate operation” pattern described in the OpenQ report (attacker floods a capped array with worthless tokens to deny funding by a legitimate token).

### Finding Description
When an AA sends a payment (`completePaymentPayload` → `readStableOutputs`/`readUnstableOutputsSentByAAs` → `iterateUnspentOutputs`), the SQL that selects candidate unspent outputs to use as inputs only excludes tiny outputs for the base asset: [1](#0-0) 

```
function readStableOutputs(handleRows) {
	// byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond
	conn.query(
		"SELECT unit, message_index, output_index, amount, output_id \n\
		FROM outputs \n\
		CROSS JOIN units USING(unit) \n\
		WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
```

The comment explicitly documents the intended anti-dust protection ("spamming the AA with very small outputs so that the AA spends all its money for fees") but the filter `amount>=FULL_TRANSFER_INPUT_SIZE` is applied only in the `asset IS NULL` (base) branch; when `asset` is set (any custom asset), the query has no lower bound on `amount` at all. The same asymmetry exists in `readUnstableOutputsSentByAAs`: [2](#0-1) 

Because `iterateUnspentOutputs` consumes rows in that unfiltered order until the target amount is reached, an attacker who has sent thousands of 1-unit outputs of the target asset to the AA will force every one of those dust outputs into the input list of the AA's next payment in that asset (since they are ordered deterministically by `main_chain_index, unit, output_index` and get consumed oldest-first before larger legitimate outputs are reached, unless the target amount is met earlier — but a determined attacker can keep the AA's own larger balance already spent/small, or simply send enough dust that any payment must traverse it).

Normally a payment message with too many inputs would be rejected by `validatePaymentInputsAndOutputs`: [3](#0-2) 

```
if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
	return callback("too many inputs");
```

but this check is explicitly bypassed for AA-authored units (`!objValidationState.bAA`), and the unit-size cap is likewise bypassed for AAs after `pemCurvesFixMci`: [4](#0-3) [5](#0-4) 

So an AA can legally build a payment with an unbounded number of dust inputs, each of which adds to `headers_commission`/`payload_commission`/oversize fee that is paid in bytes out of the AA's own balance (the very outcome the dust-attack comment in the code says it is trying to prevent for base bytes).

### Impact Explanation
An attacker with no special privileges — merely the ability to send a `payment` message of any asset the AA accepts/tracks (e.g. a token used inside the AA's business logic, or even the AA's own issued asset if it's `is_transferrable`) — can:
1. Send a large number of tiny-amount outputs of that asset to the AA address (cheap: only bytes fee for tiny asset amounts).
2. Force every future legitimate response of the AA that pays out in that asset to consume these dust inputs (unfiltered for non-base assets), massively inflating the AA response unit's size and byte fees.
3. Drain the AA's byte balance through oversize/headers/payload fees paid for handling the dust, or make the AA response bounce (`not enough funds for ... bytes`) — denying the legitimate trigger sender's expected asset payout and potentially freezing/loss of the AA's byte funds.

This matches an "AA fund loss or freezing" outcome, analogous to the OpenQ griefing bug where a shared/limited resource used to service a legitimate party could be filled with worthless entries by an unprivileged attacker to deny/degrade service.

### Likelihood Explanation
Any account can trivially construct many small-amount asset outputs to a known AA address in low-cost units (asset amounts have no minimum, only the byte cost of an output matters, which is fixed and modest). No special AA/whitelisting relationship, arbiter role, or elevated permission is required — exactly the "unprivileged unit poster / asset issuer" threat model this analog covers. The attack is more attractive for well-known AAs that pay recurring rewards/refunds in a specific non-base asset (e.g., DeFi/DEX/lottery AAs), where the attacker knows in advance the AA will need to spend from that asset's balance.

### Recommendation
Apply the same dust-amount filter used for base-asset outputs (`amount >= FULL_TRANSFER_INPUT_SIZE`, or an equivalent asset-aware minimum-value threshold) to the non-base-asset branch of `readStableOutputs` and `readUnstableOutputsSentByAAs` in `aa_composer.js`, and/or reinstate/adjust the `MAX_INPUTS_PER_PAYMENT_MESSAGE` limit for AA-authored payment messages (perhaps with a higher AA-specific ceiling) rather than fully exempting `bAA` units from it, so an AA response cannot be forced to include an unbounded number of dust inputs regardless of asset.

### Proof of Concept
1. Deploy/observe an AA that periodically pays users in a custom asset `X` (any asset that is transferable to arbitrary addresses).
2. Attacker crafts and posts many units, each sending a `payment` message with asset `X` and amount `1` (or any minimal amount) to the AA's address; repeat until thousands of tiny unspent outputs of asset `X` exist at the AA address.
3. Trigger the AA in a way that causes it to send a legitimate payment in asset `X` (e.g., normal user interaction).
4. Observe `aa_composer.js`'s `completePaymentPayload`/`readStableOutputs` picking up the dust outputs (no amount filter for non-base asset), producing a payment message with a very large number of inputs that: (a) is not rejected by `validatePaymentInputsAndOutputs`'s `MAX_INPUTS_PER_PAYMENT_MESSAGE` check because `objValidationState.bAA` is true, and (b) is not rejected by the `MAX_UNIT_LENGTH` unit-size check because that check is also bypassed for AA units post-`pemCurvesFixMci`. Confirm the resulting oversize/header fees consume the AA's byte balance disproportionately or cause the response to bounce due to insufficient bytes.

### Citations

**File:** aa_composer.js (L1140-1154)
```javascript
			function readStableOutputs(handleRows) {
			//	console.log('--- readStableOutputs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				// byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond
				conn.query(
					"SELECT unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND main_chain_index<=? \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY main_chain_index, unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
```

**File:** aa_composer.js (L1157-1173)
```javascript
			function readUnstableOutputsSentByAAs(handleRows) {
			//	console.log('--- readUnstableOutputsSentByAAs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				conn.query(
					"SELECT outputs.unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					CROSS JOIN unit_authors USING(unit) \n\
					CROSS JOIN aa_addresses ON unit_authors.address=aa_addresses.address \n\
					WHERE outputs.address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>="+FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND (main_chain_index>? OR main_chain_index IS NULL) \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY latest_included_mc_index, level, outputs.unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
			}
```

**File:** validation.js (L267-268)
```javascript
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis && !bAA)
			return callbacks.ifUnitError("unit too large");
```

**File:** validation.js (L744-744)
```javascript
					if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && objValidationState.bAA && objValidationState.last_ball_mci < constants.pemCurvesFixMci)
```

**File:** validation.js (L2137-2138)
```javascript
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
```
