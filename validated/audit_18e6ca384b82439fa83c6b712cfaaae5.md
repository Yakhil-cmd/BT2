### Title
Unbounded dust-output accumulation forces every AA payment query to scan an ever-growing, unlimited result set - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s `completePaymentPayload` builds an AA's outgoing payment by querying *all* of its unspent outputs (no `LIMIT`), sorted, and then iterating them in JS until enough value is accumulated. An unprivileged unit poster can keep sending small (but above-dust-threshold) payments to an AA address forever, permanently growing the set of unspent outputs that must be fetched and sorted by every node on every future trigger that causes that AA to send any payment — the same "iterate over unbounded, ever-growing per-address history on every operation" pattern flagged in the `TokenState.getLockedCount` finding.

### Finding Description
When an AA sends a payment, `sendUnit` → `completePaymentPayload` selects candidate inputs via: [1](#0-0) 

and [2](#0-1) 

Neither query has a `LIMIT`. The comment on `readStableOutputs` acknowledges a dust-attack concern and only filters out outputs *below* `FULL_TRANSFER_INPUT_SIZE`: [3](#0-2) 

but places no upper bound on the number of qualifying outputs. The `iterateUnspentOutputs` function then loops over the full, unbounded `rows` array in JS to accumulate `total_amount`: [4](#0-3) 

Because the SQL result set is materialized in full (and sorted with `ORDER BY main_chain_index, unit, output_index` / `ORDER BY latest_included_mc_index, level, ...`) before the JS loop can `break`, the DB-side cost (and the memory needed to hold the rows) scales with the *total number of ever-accumulated unspent outputs sent to that AA address*, not with the number actually needed to satisfy the current payment. Just like `getLockedCount` iterating over an ever-growing `delegationIds` array for a single holder, this code iterates over an ever-growing set of outputs for a single address, and this happens deterministically on **every full node** that processes the AA's trigger (required for consensus), not just once.

An attacker (any unprivileged unit poster / AA trigger sender) can post repeated small payments (just above the dust threshold, or in an asset with no dust filter at all — the asset-branch condition `amount>="+FULL_TRANSFER_INPUT_SIZE` is applied to base-asset amounts only inside the ternary, but for custom assets the filter is effectively `asset=? AND is_spent=0` with no minimum amount check at all) to the target AA faster than the AA naturally consumes them (e.g., an AA that rarely pays out, or is only occasionally triggered to send funds, or that always spends "just enough" and leaves the newest dust behind due to the FIFO/mci ordering). Over time this AA's unspent-output count on that asset grows without bound.

### Impact Explanation
This directly threatens the "AA fund loss or freezing" and "network unable to confirm new units" criteria:
- Every node validating the network must independently execute `handleTrigger` deterministically to reach the same result; if the unbounded query/array becomes too slow or memory-heavy for a given AA address, that AA's ability to respond to triggers (and thus move its own funds) degrades or stalls for the entire network simultaneously, since all full nodes must do the same work to stay in consensus.
- If the AA is a widely used contract (e.g. a DEX, bonding-curve, or custody AA) that must query its own balance/outputs to send payouts to users, this can effectively "freeze" future outgoing payments from that AA, i.e., lock its funds, mirroring the "may... lock all tokens forever" impact of the original `getLockedCount` bug.
- The cost is entirely attacker-controlled and grows monotonically forever since spent outputs are the only mechanism for shrinking the set, and an attacker can always out-pace the AA's own spending cadence with cheap dust payments.

### Likelihood Explanation
Likelihood is Medium-High: sending payments to any AA address is a normal, permissionless, low-cost action available to any user (this is exactly how triggers/payments to AAs work — no special privilege required). The dust filter only guards the base-asset amount threshold; there appears to be no equivalent minimum-amount filter enforced for the asset branch of `readStableOutputs`/`readUnstableOutputsSentByAAs`, making the attack cheap for custom assets and only moderately more expensive for the base asset (bounded by `FULL_TRANSFER_INPUT_SIZE`, i.e. still small, repeatable dust).

### Recommendation
- Add a `LIMIT` to both `readStableOutputs` and `readUnstableOutputsSentByAAs` queries (e.g., limit to the maximum number of inputs a single payment message can realistically use), and if the accumulated amount from the limited set is insufficient, either fail gracefully or paginate deterministically.
- Enforce a minimum-amount/dust filter for custom-asset outputs symmetric to the base-asset one, and/or cap the number of unspent outputs an address/asset pair is allowed to accumulate, forcing consolidation.
- Consider adding a periodic/opportunistic auto-consolidation mechanism for AA outputs so the unspent-output count cannot grow unbounded regardless of trigger frequency.

### Proof of Concept
1. Deploy or identify a target AA (`address`) that accepts payments in a given `asset` (or base) and only occasionally sends outputs from its own balance (e.g., a periodic payout AA, or one that spends only what's needed per trigger and leaves change).
2. From an unprivileged wallet, repeatedly post many small payment units to `address` (each just above `FULL_TRANSFER_INPUT_SIZE` for base asset, or arbitrarily small for a custom asset with `fixed_denominations=false`), at a rate exceeding the AA's own spending rate. Each payment simply becomes one more unspent `outputs` row for `address`.
3. Over time (weeks/months, or accelerated in a testnet with cheap fees and high throughput), `address`'s unspent-output count for that asset grows into the tens/hundreds of thousands.
4. Trigger the AA to make a payment (any trigger that invokes `sendUnit`/`completePaymentPayload`). Every full node processing that trigger's MCI-stabilization must run `readStableOutputs`/`readUnstableOutputsSentByAAs`, which now returns and sorts the entire unbounded row set before `iterateUnspentOutputs` can break early — dramatically increasing per-node processing time/memory for that single AA response and degrading the AA's ability to keep sending future payments in a timely, network-wide-agreed manner.

Note: I was unable to fully verify runtime unit-size or input-count caps that might partially bound the *number of inputs actually placed into the resulting unit* (only the *query result set* itself is confirmed unbounded, per `constants.js` `MAX_AUTHENTIFIER_LENGTH`/related constants I could not fully inspect due to index truncation). A Devin session with full repository access would be needed to confirm whether any such downstream cap mitigates the unit-construction step, though it would not mitigate the unbounded DB query/sort cost itself.

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
