This confirms the key finding: the MAX_UNIT_LENGTH check is explicitly bypassed for AA-generated units in older MCI ranges (`!bAA` in `validation.js:267`), and even after `pemCurvesFixMci` it's only checked in `validateParents` conditioned on MCI, while `MAX_INPUTS_PER_PAYMENT_MESSAGE` is unconditionally skipped for `objValidationState.bAA` in `validation.js:2137`. Combined with the dust-filtering gap in `aa_composer.js` (minimum output size is enforced only for base-asset outputs, not for custom assets), this reproduces the OpenQ bug class: an unprivileged unit poster can cheaply grow an unbounded collection of tiny spendable outputs belonging to an AA, and the AA's own coin-selection logic must later iterate that unbounded set with no cap, risking permanent inability to spend/respond in that asset.

### Title
Unbounded dust-output accumulation on AA addresses can permanently freeze an AA's ability to spend a non-base asset - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `sendUnit`/`completePaymentPayload`/`iterateUnspentOutputs` logic selects unspent outputs owned by the AA to fund a response payment. For non-base assets, the SQL queries in `readStableOutputs` and `readUnstableOutputsSentByAAs` apply no minimum-amount filter (unlike base-asset outputs, which are explicitly filtered to avoid dust attacks), and the resulting coin-selection loop is not capped by `MAX_INPUTS_PER_PAYMENT_MESSAGE` because that check is skipped whenever `objValidationState.bAA` is true in `validatePaymentInputsAndOutputs`.

### Finding Description
Any unprivileged unit poster who holds units of a divisible, non-fixed-denomination asset can send an unlimited number of extremely small-value transfers of that asset to a target AA address. Each such transfer creates a new row in the `outputs` table for that AA and asset. When the AA subsequently needs to send/forward that asset (as part of its normal application logic, e.g. `{app:'payment', payload:{asset:X, outputs:[...]}}` with `amount` or a send-all output), `completePaymentPayload` calls `readStableOutputs`/`readUnstableOutputsSentByAAs` to fetch all unspent outputs of that asset owned by the AA: [1](#0-0) 

Note that the dust filter (`amount>=FULL_TRANSFER_INPUT_SIZE`) is applied only to the base asset branch of the WHERE clause; the asset branch has no minimum-amount condition: [2](#0-1) 

The returned rows (unbounded in count, no SQL `LIMIT`) are then iterated in `iterateUnspentOutputs`, one input added per dust output, until enough value is accumulated: [3](#0-2) 

Normally, `validatePaymentInputsAndOutputs` in `validation.js` caps the number of inputs per payment message via `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE`, but this check is explicitly bypassed for AA-composed units: [4](#0-3) 

This is the exact bug class from the report: an attacker can cheaply grow an array/collection of tiny "deposits" (here, tiny asset outputs) that a privileged operation (here, the AA's own fund-management logic) must iterate over in full, with no bound, in order to complete a legitimate operation (here, spending/forwarding the asset).

### Impact Explanation
If the number of dust outputs grows large enough, `sendUnit` must include all of them as inputs in a single unit. This inflates `objUnit.headers_commission + objUnit.payload_commission`, which is checked against `constants.MAX_UNIT_LENGTH` in `validateParents`/`validate`, but that check is itself conditionally skipped for AA units depending on MCI (`&& !bAA` in `validation.js:267`, and only enforced pre-`pemCurvesFixMci` in `validateParents` at `validation.js:744`). Even where the size check does apply, once triggered the AA's response unit fails validation and the response bounces — since the underlying dust outputs remain unspent and still too numerous to consolidate in one unit, the AA can become permanently unable to move that asset out, i.e., a durable freeze of AA-held asset funds. Where the size check is bypassed, the resulting oversized/slow-to-build unit represents a node-side resource-exhaustion condition each time every node re-derives that AA response deterministically, which can stall confirmation of that AA's outputs across the network. This matches the required impact category of "AA fund loss or freezing" / "network unable to confirm new units".

### Likelihood Explanation
The attack requires only that the attacker hold (or issue, if the asset is not `issued_by_definer_only`) minuscule amounts of an existing asset and repeatedly send tiny transfers of it to the target AA — inexpensive compared to a normal payment, since payment fees are based on unit size/bytes rather than the transferred asset amount, and there is no dust threshold enforced for asset outputs analogous to the base-asset one. Any AA that accepts and later forwards/sends a non-base asset (common pattern, e.g. DEXs, asset wrappers, token bridges) is a viable target. The comment in the code (`aa_composer.js:1144`) shows developers were already aware of exactly this dust-attack vector for the base asset, but the same protection was not extended to custom assets.

### Recommendation
Apply a minimum-amount (dust) filter to asset outputs in `readStableOutputs`/`readUnstableOutputsSentByAAs` in `aa_composer.js`, similar to the existing `FULL_TRANSFER_INPUT_SIZE` filter used for base-asset outputs, calibrated relative to the marginal input-size cost. Additionally, enforce `MAX_INPUTS_PER_PAYMENT_MESSAGE` (or an equivalent cap) uniformly for AA-generated payment messages rather than exempting `objValidationState.bAA`, and ensure the `MAX_UNIT_LENGTH` check is unconditionally enforced for AA response units regardless of MCI, so an oversized response bounces cleanly and predictably rather than silently growing unbounded.

### Proof of Concept
1. Attacker (address `M`) holds a divisible, non-fixed-denomination custom asset `A` (self-issued or otherwise obtained).
2. Attacker crafts and posts N units, each containing a `payment` message with `asset: A` and a single output `{address: <AA_address>, amount: 1}` sent to a target AA that is known to forward/spend asset `A` in its response logic.
3. Each unit creates one new row in `outputs` for `(address=<AA_address>, asset=A, amount=1, is_spent=0)`; no dust filter blocks this because `readStableOutputs`'s asset branch has no `amount>=` condition (`aa_composer.js:1144-1153`).
4. A legitimate user later triggers the AA in a way that causes it to send/forward asset `A` (e.g., a send-all output or a fixed-amount output funded from the AA's own asset balance).
5. `completePaymentPayload`→`readStableOutputs` returns all N dust rows with no `LIMIT`; `iterateUnspentOutputs` must add each as an input since each contributes only `amount:1` toward the target amount (`aa_composer.js:1102-1138`).
6. Because `validatePaymentInputsAndOutputs` skips the `MAX_INPUTS_PER_PAYMENT_MESSAGE` check when `objValidationState.bAA` is true (`validation.js:2137-2138`), the resulting payment message can contain arbitrarily many inputs, growing `objUnit.payload_commission` without bound; depending on MCI, this either bypasses the `MAX_UNIT_LENGTH` check (unit accepted but abnormally large/slow) or fails it and bounces (unit rejected, response never delivered, asset `A` remains stuck in the AA), demonstrating denial of the AA's ability to spend/forward its `A` balance.

### Citations

**File:** aa_composer.js (L1102-1138)
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
					var additional_output_size = is_base ? OUTPUT_SIZE + (bWithKeys ? OUTPUT_KEYS_SIZE : 0) : 0; // the same for send-all
					var change_amount = total_amount - (net_target_amount + additional_output_size + getOversizeFee(size + additional_output_size));
					if (change_amount > 0) {
						bFound = true;
						if (send_all_output) {
							console.log("change " + change_amount + ", storage_size " + storage_size);
							send_all_output.amount = change_amount;
						}
						else {
							payload.outputs.push({ address: address, amount: change_amount });
							break;
						}
					}
				}
			}
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

**File:** validation.js (L2137-2138)
```javascript
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
```
