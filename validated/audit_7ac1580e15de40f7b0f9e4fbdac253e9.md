### Title
Dust byte outputs sent to an Autonomous Agent below `FULL_TRANSFER_INPUT_SIZE` can become permanently stuck and unspendable - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `completePaymentPayload()` selects unspent outputs owned by the triggered AA as inputs for its response payment via `readStableOutputs()` and `readUnstableOutputsSentByAAs()`. For the base asset, both queries filter candidate outputs with `amount >= FULL_TRANSFER_INPUT_SIZE`, explicitly to avoid "dust" outputs that are net-negative to spend. [1](#0-0) [2](#0-1) 

### Finding Description
Any base-asset (bytes) output sent to an AA address with an amount smaller than `FULL_TRANSFER_INPUT_SIZE` is excluded from both the "stable outputs" and "unstable outputs sent by AAs" queries used to gather spendable inputs when the AA composes a payment response:
```
WHERE address=? AND asset ... IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE ...
``` [3](#0-2) 

This is analogous to the reported issue: a fixed, non-zero minimum threshold gates whether funds already resting at a given address (the AA, analogous to the EigenPod) can ever be picked up and moved out again. Because the SQL query itself excludes such small outputs from being counted as available balance for input selection, the AA has no code path that will ever select such an output as an input in any future trigger — the dust is permanently unreachable by the AA's own payment-composition logic, regardless of how many times the AA is triggered afterward. Unlike a legitimate dust-attack defense (which is intended to prevent third parties spamming the AA with tiny outputs to drain its balance on fees), the same filter also blocks recovery of dust that arrives as legitimate residual change (e.g. a user under- or over-paying by a few bytes, or the AA's own change output falling under the threshold from a formula miscalculation), permanently freezing those funds at the AA's address.

### Impact Explanation
Bytes below the `FULL_TRANSFER_INPUT_SIZE` threshold that end up as a UTXO owned by an AA address are permanently frozen: the AA can never construct a payment message that spends them, because the input-selection queries never surface them as inputs. This constitutes AA fund freezing — the core impact criterion for a Medium/High finding in this space (funds move from "spendable AA balance" to permanently unspendable, unrecoverable balance without any owner control or admin-bypass).

### Likelihood Explanation
This can be triggered unintentionally in normal AA operation whenever a dust-sized base-asset output ends up at the AA's address (e.g., change output arithmetic producing a sub-threshold remainder, or a user constructing a payment whose leftover to the AA is a few bytes under the cutoff). No malicious actor or privileged role is required — a normal AA trigger sender can cause this state, making it reachable by any unprivileged unit poster interacting with an AA.

### Recommendation
Provide an explicit sweep/consolidation path for sub-threshold dust outputs — e.g., allow the AA's own logic (or a dedicated internal mechanism) to aggregate multiple dust outputs together so their combined value clears `FULL_TRANSFER_INPUT_SIZE` before being excluded, or relax the filter to allow spending dust outputs when they are combined with other outputs in the same input-selection pass rather than filtering them out of the candidate set entirely.

### Proof of Concept
1. Construct or observe an AA balance state where the AA's address owns a base-asset output with `amount < FULL_TRANSFER_INPUT_SIZE` (e.g. due to a change/remainder calculation in a previous AA response, per the change-output logic in `completePaymentPayload()`) [4](#0-3) .
2. Trigger the AA again requesting a full/send-all payment of the base asset.
3. `readStableOutputs` / `readUnstableOutputsSentByAAs` run with `amount >= FULL_TRANSFER_INPUT_SIZE`, so the dust output is never included in `iterateUnspentOutputs`, and is never selected as an input in any subsequent trigger either. [5](#0-4) 
4. The dust remains permanently unspent at the AA's address across all future triggers, since no other code path in `completePaymentPayload` bypasses this filter.

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

**File:** aa_composer.js (L1124-1136)
```javascript
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
