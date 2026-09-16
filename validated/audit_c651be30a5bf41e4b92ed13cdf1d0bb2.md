Based on the investigation, the strongest reachable analog to the "unbounded loop over an attacker-inflatable array" bug class in `ocore` is in the AA response-composition code path, not in the oscript/formula evaluator (which already caps loop counts, array literal sizes, recursion depth, and overall complexity/op budgets via `constants.MAX_COMPLEXITY`/`MAX_OPS` in `definition.js`, `formula/validation.js`, and `formula/evaluation.js`).

### Title
Unbounded consumption of attacker-seeded dust outputs during AA payment composition can freeze AA asset funds - (File: aa_composer.js)

### Summary
When an Autonomous Agent (AA) sends a payment message in response to a trigger, `aa_composer.js`'s `completePaymentPayload`/`iterateUnspentOutputs` selects unspent outputs belonging to the AA address and pushes them one-by-one into `payload.inputs` until the target amount is reached. For custom (non-base) assets, the output-selection SQL query in `readStableOutputs`/`readUnstableOutputsSentByAAs` applies no minimum-amount ("dust") filter, unlike base-asset outputs, which are explicitly filtered by `amount>=FULL_TRANSFER_INPUT_SIZE` "to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond" (comment at `aa_composer.js:1144`).

### Finding Description
Any unprivileged unit poster can send an arbitrarily large number of tiny-amount outputs of a custom asset to an AA address (a private-payment counterparty or asset issuer/poster can trivially do this at negligible cost per output, since fees scale with unit size, not with the number of outputs an attacker chooses to fragment across many small units over time). Because the non-base-asset branch of the output-selection query at `aa_composer.js:1149` and `aa_composer.js:1167` has no dust threshold, all of this attacker-created dust becomes eligible for consumption by the AA. When the AA later composes a payment in that asset, `iterateUnspentOutputs` (`aa_composer.js:1102-1137`) loops over the returned rows and unconditionally appends each as an input to `payload.inputs`, exactly mirroring the "mass update" pattern where an unbounded, externally-grown array is iterated in full inside a single execution — except here the iteration happens synchronously inside AA-trigger processing (`main_chain.js` `stabilizeMci` → `aa_composer.handleAATriggers`), which runs during main-chain stabilization, a path every node must execute to reach consensus. [1](#0-0) [2](#0-1) 

### Impact Explanation
If the number/size of dust outputs pushed into `payload.inputs` grows large enough, the resulting unit can exceed protocol size limits (unit/message length, max inputs per message) causing the payment composition to fail and the AA to bounce the trigger — the trigger's payment is lost as it's returned minus fees, while the underlying dust problem persists unresolved. Because every subsequent attempt to spend that asset balance re-runs the same unbounded selection over the same (or growing) dust set, the AA's balance in that asset can become effectively unspendable/frozen. This falls under "AA fund loss or freezing," one of the accepted concrete impacts.

### Likelihood Explanation
Any address controller (attacker) can trigger the condition simply by paying small amounts of any custom asset it controls to a target AA address — no special privilege is required, matching the "asset issuer / unprivileged unit poster" reachability requirement. Because ocore already explicitly recognizes and defends against exactly this dust-DoS pattern for the base asset (see the comment at `aa_composer.js:1144`), the omission of an equivalent safeguard for custom assets appears to be an oversight rather than an intentional design choice.

### Recommendation
Apply an equivalent minimum-amount/dust filter to non-base-asset output selection in `readStableOutputs` and `readUnstableOutputsSentByAAs` (e.g., ignore asset outputs below a size- or fee-relative threshold, or cap the number of inputs consumed per payment composition with a `LIMIT` and fall back to partial-completion aggregation over multiple executions), analogous to the `amount>=FULL_TRANSFER_INPUT_SIZE` protection already applied to the base asset.

### Proof of Concept
1. An attacker deploys/uses a custom asset (`XYZ`).
2. Attacker sends many separate units each transferring `1` unit of asset `XYZ` to a target AA's address (cost is bounded by normal per-unit fees, not by output count constraints).
3. A legitimate user triggers the AA in a way that causes it to send a payment in asset `XYZ` from its balance.
4. `completePaymentPayload` invokes `readStableOutputs`/`readUnstableOutputsSentByAAs` with no dust filter for asset `XYZ`, returning the full set of attacker-seeded tiny outputs; `iterateUnspentOutputs` pushes all of them into `payload.inputs` before the target amount can be met (since each contributes only `1` unit), producing an oversized unit or a failed/bounced payment.
5. Repeating steps 1–2 for the same asset perpetually re-creates the condition, effectively freezing the AA's ability to move its `XYZ` balance.

**Note on limitations:** I did not have access to the exact enforcement logic that would reject an oversized unit (e.g., `MAX_INPUTS`-per-message constant referenced in `validation.js`/`constants.js`) or confirm precisely how `aa_composer.js` handles a bounce when input selection fails to complete under size constraints; a full trace of that failure/bounce path (and whether partial progress could be made across multiple trigger executions) would require deeper reading of `validation.js` input-count limits and the `bounce()` handling in `aa_composer.js`, which the current index did not fully surface.

### Citations

**File:** aa_composer.js (L1102-1137)
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
```

**File:** aa_composer.js (L1140-1173)
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
