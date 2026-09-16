### Title
Unbounded input accumulation in AA response payments bypasses `MAX_INPUTS_PER_PAYMENT_MESSAGE`, allowing an attacker to permanently freeze an AA's asset balance - (File: aa_composer.js)

### Summary
`validatePaymentInputsAndOutputs` in `validation.js` caps the number of inputs a payment message can carry, but explicitly exempts AA-generated units from this cap. Combined with the unlimited output-selection query used when an AA composes a payment response, this lets an unprivileged unit poster force an AA to try to consume an attacker-controlled, unbounded number of tiny outputs in a single response, which can never be validated/completed, freezing the AA's ability to pay out that asset.

### Finding Description
When validating ordinary (user-submitted) payments, the input count is bounded: [1](#0-0) 
Note the `&& !objValidationState.bAA` — payment messages produced by an AA (bAA === true) are **not** subject to `MAX_INPUTS_PER_PAYMENT_MESSAGE`.

When an AA needs to build a payment message (e.g. forwarding a received custom asset back to a sender, a very common AA pattern), `aa_composer.js`'s `completePaymentPayload`/`iterateUnspentOutputs` selects unspent outputs at the AA's address and keeps adding them as inputs until the target amount is reached: [2](#0-1) 

The source outputs are fetched with `readStableOutputs`, which issues an unbounded SQL query (no `LIMIT`) for **all** unspent outputs of the relevant asset at that address: [3](#0-2) 

Critically, the dust-filtering protection mentioned in the code (`amount>=FULL_TRANSFER_INPUT_SIZE`) is applied **only to the base asset** branch of the query, not to custom (non-base) assets: [4](#0-3) 

Since arbitrary users can freely issue/transfer custom assets to any address (including AA addresses) via ordinary payments, and ordinary payment outputs for non-base assets have no minimum-amount floor, an attacker can send a very large number of minimal-amount outputs of a custom asset to an AA address. Because AAs are exempt from `MAX_INPUTS_PER_PAYMENT_MESSAGE`, and the output-selection query has no `LIMIT`, once the AA is triggered to send back or forward that asset, `iterateUnspentOutputs` will attempt to fold all of the attacker's dust outputs into a single payment message as inputs.

This mirrors the reported bug class exactly: a function that iterates over an attacker-influenced, unbounded set of "positions" (here, UTXOs) in a single transaction/response, with no batching, causing the operation to become impractically large/expensive.

### Impact Explanation
The resulting AA response unit would contain thousands of inputs in one payment message, making the unit extremely large. This can:
- Cause the unit to fail size-related checks (e.g. `oversize_fee`/message-size accounting) inconsistently or push resource usage far beyond what is normal, potentially causing `validateAndSaveUnit`/`writer.saveJoint` to fail repeatedly.
- Since `handleTrigger` runs under the AA-trigger processing pipeline (serialized via `mutex.lock(['aa_triggers'])` in `handleAATriggers`), a pathological response computation blocks processing of subsequent AA triggers for other users, and the AA itself becomes stuck bouncing forever, unable to ever pay out or forward the targeted asset — an AA fund-freezing condition, since the outputs remain unspendable while blocking legitimate usage of the AA.
- Every time the AA is triggered, it re-attempts to gather the same huge set of dust outputs, so the condition is not self-healing without a code fix or manual intervention, meeting the "AA fund loss or freezing" acceptance criterion.

### Likelihood Explanation
Reaching this condition requires only sending ordinary custom-asset payments to a public AA address (no special privilege), which is core, expected `ocore` functionality (asset issuance + payment). Any attacker who identifies an AA that echoes or forwards a custom asset back to senders (a routine AA pattern, e.g. swap/DEX-style AAs) can spam it with a large number of low-value payments prior to triggering the vulnerable code path. This is a Medium-severity, realistically reachable griefing/freezing vector matching the acknowledged upstream report's "medium" severity class.

### Recommendation
- Apply the same `MAX_INPUTS_PER_PAYMENT_MESSAGE` cap to AA-generated payment messages, or introduce a dedicated, smaller batch limit for AA responses.
- Extend the dust-filtering minimum-amount protection in `readStableOutputs`/`readUnstableOutputsSentByAAs` to non-base assets as well, so an attacker cannot cheaply create a large number of tiny spendable outputs at an AA address.
- Add a `LIMIT` clause to the output-selection queries in `aa_composer.js` and have the AA response logic explicitly bounce/handle the "too many inputs required" case gracefully instead of silently trying to build an oversized unit.

### Proof of Concept
1. Deploy (or identify) an AA whose response logic sends back/forwards a received custom asset to the trigger address (a standard pattern).
2. Issue a custom asset and, in a loop, send many minimal-amount payments of that asset to the AA's address as ordinary payment outputs (no dust-floor check applies to non-base assets, per `aa_composer.js:1149`).
3. Send a trigger unit that causes the AA to attempt to forward/return the accumulated asset balance.
4. Observe that `completePaymentPayload`/`iterateUnspentOutputs` (`aa_composer.js:1102-1155`) pulls in all attacker-created dust outputs as inputs without any cap (since `validation.js:2137`'s `MAX_INPUTS_PER_PAYMENT_MESSAGE` check is bypassed for `objValidationState.bAA`), producing an oversized/invalid response unit and causing the AA to repeatedly bounce or fail on every subsequent trigger involving that asset.

### Citations

**File:** validation.js (L2137-2140)
```javascript
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
	if (payload.outputs.length > constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE && !storage.isGenesisUnit(objUnit.unit))
		return callback("too many outputs");
```

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
