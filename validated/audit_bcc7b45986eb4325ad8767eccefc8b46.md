### Title
Dust-output flooding of an Autonomous Agent's non-base-asset balance can permanently freeze that asset inside the AA - (File: `aa_composer.js`)

### Summary
The reported bug is a class of "targeted array/queue flooding": an unprivileged actor registers many low-value entries against a victim's account, and the code that must later enumerate *all* of those entries to pay out the victim becomes unusable (gas/size limits), freezing the victim's funds. In `ocore`, the analogous unprivileged, permissionless registration channel is a plain payment message: anyone can send an unlimited number of dust outputs of a custom asset to an Autonomous Agent (AA) address. When the AA later tries to spend that asset (e.g., to pay out a legitimate user), `aa_composer.js` collects *all* unspent outputs of that asset with no minimum-amount filter and no cap on the number of inputs gathered, unlike the equivalent code path for the base asset (bytes), which explicitly filters out dust to defend against exactly this attack.

### Finding Description
In `aa_composer.js`, `completePaymentPayload`'s `readStableOutputs`/`readUnstableOutputsSentByAAs` functions build the list of unspent outputs an AA can use as inputs when composing a response payment: [1](#0-0) 

The comment on line 1144 explicitly documents that byte (base-asset) outputs smaller than `FULL_TRANSFER_INPUT_SIZE` (≈60 bytes) are excluded "to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond." That filter is applied only when `asset` is null (i.e., only for the base asset): `"...AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+"..."`. When `asset` is a custom asset, no minimum-amount condition is applied at all, so every dust output of that asset sitting at the AA's address is selected as a candidate input.

`iterateUnspentOutputs` then pushes every returned row into `payload.inputs` until the target amount is reached, with no bound on the number of inputs consumed: [2](#0-1) 

Crucially, the normal anti-spam limits that would otherwise cap the number of inputs or the overall unit size are explicitly bypassed for AA-generated units: [3](#0-2) [4](#0-3) 

`payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` is only enforced `&& !objValidationState.bAA`, and the overall `MAX_UNIT_LENGTH` check is skipped `&& !bAA`. This means an AA response unit can legally contain far more inputs and be far larger than what a normal unit is allowed to be, precisely so that AAs can consolidate legitimate large numbers of inputs — but this also removes the safety net that would otherwise stop a dust-input explosion from producing an oversized, unaffordable response.

Because sending outputs to any address (including an AA address) requires no permission or registration (any unit poster can target any address with a `payment` message, exactly like the report's "anyone can deploy their own vaults bypassing the factory" step), an attacker can flood a target AA with thousands of dust outputs of a custom asset that the AA holds/manages. When the AA is later triggered to pay out that asset to a legitimate counterpart, `readStableOutputs`/`readUnstableOutputsSentByAAs` will pull in all (or very many) of the attacker's dust outputs as inputs, inflating `payload_commission`/`oversize_fee` far beyond what the AA can afford from its byte balance, causing the response to bounce with "not enough funds" repeatedly (see `checkAAOutputs`/bounce-fee logic referencing `MissingBounceFeesErrorMessage`). Because the dust outputs remain unspent and keep being re-selected by the same unbounded query on every subsequent attempt, the condition does not resolve itself — the asset balance inside the AA becomes effectively unspendable, mirroring the report's "forced to wait for the whole period to get any rewards" scenario, except here the AA's counterparties can be frozen out of an asset indefinitely.

### Impact Explanation
This is an AA fund-freezing vulnerability: a legitimate user or the AA's own accounting can be prevented from ever completing a payout of a custom asset once an attacker floods that asset's balance at the AA's address with dust, because the code path responsible for gathering spendable inputs has no dust filter and no cap for non-base assets, and the unit-size/input-count safety limits that would normally bound the damage are deliberately disabled for AA-generated units. This matches the accepted impact classes of "AA fund loss or freezing."

### Likelihood Explanation
Likelihood is high: sending payment outputs to an arbitrary address, including any AA, requires no special privilege, cost is only the small per-output amount plus a normal transaction fee, and the number of dust outputs needed to make an AA's future asset transfer prohibitively expensive is bounded only by the attacker's willingness to pay minor bytes fees. Any AA that manages or forwards a custom asset on behalf of users (common pattern for tokenized deposits/rewards) is exposed.

### Recommendation
Apply the same anti-dust filtering used for the base asset to custom assets in `readStableOutputs` and `readUnstableOutputsSentByAAs` in `aa_composer.js` — i.e., require `amount` to exceed some meaningful multiple of the marginal input cost (analogous to `FULL_TRANSFER_INPUT_SIZE`) regardless of whether `asset` is set. Additionally, consider re-enabling (or introducing an AA-specific but still bounded) cap on the number of inputs an AA-generated payment message may consume per response, so a flood of dust cannot arbitrarily inflate a single AA response's size/fees even if some dust filtering is bypassed.

### Proof of Concept
1. Attacker identifies a target AA address that holds/forwards a custom asset `X` (e.g., a rewards or vault-like AA).
2. Attacker repeatedly posts ordinary `payment` messages transferring asset `X` in very small amounts (e.g., 1 unit) directly to the AA's address — this requires no interaction with the AA's own logic and no special permission, exactly like directly deploying a vault referencing a victim owner bypasses the factory in the original report.
3. Once thousands of dust outputs of asset `X` sit at the AA's address, a legitimate user triggers the AA to pay out asset `X` (e.g., withdrawing a balance or receiving a reward).
4. In `aa_composer.js`, `readStableOutputs` (asset branch, `aa_composer.js:1145-1154`) selects all unspent `X` outputs at the AA's address with no minimum amount, and `iterateUnspentOutputs` (`aa_composer.js:1102-1116`) accumulates them all into `payload.inputs`.
5. Because `validation.js:2137` and `validation.js:267` both exempt AA-generated units from the input-count and unit-size limits, the resulting response payload becomes very large, and its `payload_commission`/`oversize_fee` exceeds the AA's byte balance, causing the trigger to bounce for insufficient bounce fees.
6. Since the dust outputs remain unspent after the bounce, every subsequent attempt to pay out asset `X` from the AA repeats the same failure, permanently freezing that asset balance for legitimate users of the AA.

### Citations

**File:** aa_composer.js (L1102-1116)
```javascript
			function iterateUnspentOutputs(rows) {
				for (var i = 0; i < rows.length; i++){
					var row = rows[i];
					var input = { unit: row.unit, message_index: row.message_index, output_index: row.output_index };
					arrUsedOutputIds.push(row.output_id);
					arrConsumedOutputs.push({asset: asset || 'base', amount: row.amount});
					payload.inputs.push(input);
					total_amount += row.amount;
					if (is_base) {
						net_target_amount += FULL_TRANSFER_INPUT_SIZE;
						size += FULL_TRANSFER_INPUT_SIZE;
						target_amount = net_target_amount + getOversizeFee(size);
					}
					if (total_amount < target_amount)
						continue;
```

**File:** aa_composer.js (L1140-1155)
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
			}
```

**File:** validation.js (L267-268)
```javascript
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis && !bAA)
			return callbacks.ifUnitError("unit too large");
```

**File:** validation.js (L2137-2140)
```javascript
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
	if (payload.outputs.length > constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE && !storage.isGenesisUnit(objUnit.unit))
		return callback("too many outputs");
```
