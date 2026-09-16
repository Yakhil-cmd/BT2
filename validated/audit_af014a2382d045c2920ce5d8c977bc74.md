## Title
Unbounded input enumeration when an AA pays out a custom asset can DoS the AA's response and burn trigger fees - (File: aa_composer.js, validation.js)

### Summary
`Quest.claim`'s DOS stems from an unbounded, attacker-inflatable enumeration of "tokens owned by an address" that is then iterated in a single call/transaction with no gas ceiling. Ocore has a directly analogous pattern: when an AA composes a payment response, it enumerates **all** unspent outputs of an asset held by the AA address with no `LIMIT`, and appends them one by one as payment inputs. Unlike the base-asset ("bytes") path, the custom-asset path has no dust-size floor, and validation explicitly waives the max-inputs limit for AA-generated units, so a griefer can inflate an AA's own asset-output set until responding becomes unbounded/oversized and fails.

### Finding Description
In `aa_composer.js`'s `sendUnit()` → `completePaymentPayload()`, when the AA needs to fund a payment in an asset, it reads unspent outputs of that asset belonging to the AA address with no cap on rows returned: [1](#0-0) 

For the base asset, dust-sized outputs (< `FULL_TRANSFER_INPUT_SIZE`) are filtered out specifically "to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond" — but this protection is **only applied when `asset` is null**; for any custom asset the `WHERE` clause has no minimum-amount condition at all: [2](#0-1) 

`iterateUnspentOutputs()` then walks through every returned row, unconditionally pushing each into `payload.inputs` until the target amount is reached: [3](#0-2) 

Normally a payment message's input count is capped by `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` in `validatePaymentInputsAndOutputs`, but that check is explicitly bypassed for AA-generated units: [4](#0-3) 

So any unprivileged user (or asset issuer) can send an AA address a very large number of tiny outputs of any custom asset it controls/uses (a "griefer" analog to sending dust NFTs to a Quest claimant). When the AA is later triggered to pay out in that same asset (e.g. change/reward payouts, a common AA pattern), `readStableOutputs`/`iterateUnspentOutputs` will attempt to consume all of these dust outputs as inputs — unbounded by the normal input-count validation rule — inflating the response unit's size/oversize fee calculation, exhausting the AA's byte balance on oversize fees, or producing a unit that fails size/message limits (`MAX_MESSAGES_PER_UNIT`, unit size limits) downstream and bounces.

### Impact Explanation
This is a fund-loss/availability issue reachable purely by posting normal asset-transfer units to an AA's address (no privileged role required), matching the "AA trigger sender / asset issuer" reachability class:
- The AA's response computation can fail or become prohibitively expensive to fund from its own balance (oversize fee scales with the number of forced inputs), draining/freezing AA funds intended for legitimate users.
- If the response construction fails, the trigger falls back to bouncing, burning the triggering unit's attached bytes as a bounce fee for a state that a griefer engineered, harming an unrelated legitimate user whose trigger happened to require paying out in the polluted asset.
- Because the fix that already exists (dust filtering) was deliberately applied only to the base asset, this shows the developers recognized this exact bug class but left custom assets unprotected.

### Likelihood Explanation
Any address can freely send many small-amount outputs of a chosen asset to a target AA address; this requires only ordinary payment messages, is inexpensive per dust output relative to potential damage, and needs no compromise of governance, hubs, or witnesses. AAs that pay out in custom assets (a common AA/DeFi pattern) are all exposed similarly to the original Quest.claim scenario where an attacker inflates the addressed party's UTXO-like set to drive the victim past processing limits.

### Recommendation
Apply the same anti-dust floor used for the base asset to custom-asset outputs (e.g., a minimum spendable output size relative to the asset's typical unit economics), and/or enforce `MAX_INPUTS_PER_PAYMENT_MESSAGE` (or a similarly enumerable cap) even for AA-generated payment messages, splitting responses across multiple secondary AA-triggered payments if more inputs are legitimately required, rather than exempting AA units from the input-count check entirely.

### Proof of Concept
1. Attacker repeatedly sends `N` tiny outputs (below any reasonable "useful" amount) of asset `X` to AA address `A`, where `X` is an asset that `A` is expected to pay out from in response to normal triggers.
2. A legitimate user sends a normal trigger to `A` that causes `A` to compose a `payment` message in asset `X`.
3. In `completePaymentPayload`, `readStableOutputs` (no dust filter for `asset != null`, `aa_composer.js:1144-1154`) returns all `N` dust outputs; `iterateUnspentOutputs` (`aa_composer.js:1102-1123`) appends all of them as inputs since none individually satisfies the target amount.
4. `validatePaymentInputsAndOutputs`'s `MAX_INPUTS_PER_PAYMENT_MESSAGE` check is skipped because `objValidationState.bAA` is true (`validation.js:2137`), so the oversized input set is accepted or the response unit becomes too large/expensive and the trigger bounces, burning the triggering unit's attached bytes and/or exhausting `A`'s spare byte balance on oversize fees.

### Citations

**File:** aa_composer.js (L1102-1123)
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
					if (total_amount === target_amount && payload.outputs.length > 0) {
						bFound = true;
						if (send_all_output)
							continue;
						else
							break;
					}
```

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

**File:** validation.js (L2136-2138)
```javascript
	var total_input = 0;
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
```
