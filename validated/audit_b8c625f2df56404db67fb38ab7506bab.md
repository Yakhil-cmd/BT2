### Title
Unbounded loop over an AA's unspent outputs enables dust-inflation DoS that can freeze AA funds / stall response construction - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s payment-completion logic for an autonomous agent (AA) reads and loops over **all** of the AA's unspent outputs with no size cap, similar in structure to the `openPositions[]` pattern in the referenced report (an ever-growing, per-address array that a later operation must fully traverse).

### Finding Description
When an AA constructs a response payment, `completePaymentPayload` queries all unspent outputs belonging to the AA address and consumes them one by one in `iterateUnspentOutputs`: [1](#0-0) 

The SQL query backing this loop has no `LIMIT` and simply selects every unspent output for the address/asset: [2](#0-1) 

Crucially, for a "send-all" output the loop is designed to `continue` through every remaining row instead of breaking early once the target amount is reached, i.e. it deliberately drains the entire unspent-output set: [3](#0-2) 

Any unprivileged unit poster can send many small (but not dust-filtered, i.e. `amount >= FULL_TRANSFER_INPUT_SIZE`) payments to a target AA address. Each payment creates one more row in `outputs` with `is_spent=0` for that AA. There is no bound on how many such outputs a single address can accumulate, so `state.openPositions[]`-style growth applies here to the AA's unspent-output set.

The resulting `payload.inputs` array is not subject to the normal per-message input cap, because AA-composed payments are explicitly exempted from `MAX_INPUTS_PER_PAYMENT_MESSAGE`: [4](#0-3) 

So an attacker can inflate the number of inputs an AA must use in a "send-all" response arbitrarily, since validation does not cap it for `objValidationState.bAA` triggers.

### Impact Explanation
- Every full node must deterministically re-execute the same AA trigger during validation/stabilization, so the unbounded query + unbounded JS loop is executed by all nodes processing that AA, not just the one composing the response — this is a consensus-critical computation, not a client-side convenience path.
- If the accumulated output count is large enough, the resulting response unit (with an unbounded `inputs` array) can become impractically large or slow to construct/serialize/sign, causing the AA's "send-all" logic to fail to produce a valid response within practical constraints, effectively **freezing the AA's funds** — the AA can never successfully sweep/send all of its balance because doing so requires consuming every dust output ever received.
- Because the entire node population executing this AA must do the same expensive, unbounded work, this can also stall processing of that AA's triggers network-wide, an availability/stalling condition analogous to the "no new trades / liquidation malfunction" impact described in the reference report.

This satisfies the "AA fund loss or freezing" / "network unable to process" criteria required by the validation rules.

### Likelihood Explanation
Reaching this path only requires an unprivileged unit poster to send many small payments to a known AA address (payments above `FULL_TRANSFER_INPUT_SIZE` bypass the existing dust-attack mitigation comment in the code, which only protects against sub-`FULL_TRANSFER_INPUT_SIZE` dust). No special privileges, races, or trusted roles are needed — any wallet can post ordinary payment units to a public AA address. The likelihood of triggering the unbounded loop is high for any AA that performs "send-all" logic (a common AA pattern) and that has no independent filtering of the number/size of inputs it aggregates.

### Recommendation
- Add an upper bound (e.g., a `LIMIT` clause) to the `readStableOutputs` / `readUnstableOutputsSentByAAs` queries in `aa_composer.js`, and correspondingly cap `iterateUnspentOutputs`/`payload.inputs.length`, falling back to leaving remaining balance unswept (documented AA semantics) rather than trying to consume unlimited UTXOs in one message.
- Remove or tighten the `!objValidationState.bAA` exemption for `MAX_INPUTS_PER_PAYMENT_MESSAGE` in `validation.js`, or introduce an AA-specific cap that is enforced consistently with what `aa_composer.js` can safely produce.
- Consider consolidating/merging small outputs automatically (background compaction) or increasing the effective dust threshold (`FULL_TRANSFER_INPUT_SIZE`) to reduce practical growth of long-lived unspent-output sets per AA.

### Proof of Concept
1. Deploy an AA that, upon receiving any trigger, responds with a payment message using send-all semantics (a common bounce-back-with-fees or "sweep balance" pattern).
2. From an unprivileged account, repeatedly post many small payment units to the AA address, each output amount set just above `FULL_TRANSFER_INPUT_SIZE` (so it isn't filtered as dust), accumulating a very large number of unspent outputs for the AA over time.
3. Trigger the AA's send-all response. `completePaymentPayload`'s `readStableOutputs` query returns all accumulated unspent outputs (unbounded), and `iterateUnspentOutputs` loops through and consumes every one of them into `payload.inputs` because send-all causes the loop to `continue` rather than `break` early.
4. Because `objValidationState.bAA` exempts the resulting payment from `MAX_INPUTS_PER_PAYMENT_MESSAGE`, the check in `validation.js` at lines 2137-2138 does not reject the oversized input list, letting the constructed unit grow in proportion to the number of dust outputs the attacker created — degrading or preventing successful AA fund sweeps and burdening every full node that must replay this same AA execution deterministically.

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
