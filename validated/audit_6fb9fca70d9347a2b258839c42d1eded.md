### Title
Unbounded per-output SQL scan when an AA composes a payment lets an attacker inflate its unspent-output set and stall/DoS deterministic AA execution across all full nodes - ([File: aa_composer.js])

### Summary
The Sherlock report describes a StakeDAO contract where a claim function's cost grows linearly (with nested iteration) with the number of unclaimed cycles/history entries an attacker or normal usage lets accumulate, eventually exceeding the Ethereum block gas limit and permanently bricking the claim. The reachable analog in this Obyte (`ocore`) codebase is `completePaymentPayload`'s `readStableOutputs` / `iterateUnspentOutputs` logic used when an Autonomous Agent (AA) composes an outgoing `payment` message in `aa_composer.js`: it selects **all** unspent outputs of the AA's address/asset with no `LIMIT`, and then loops over the rows in JavaScript to accumulate enough value for the AA's requested payment. Because every payment sent to an AA leaves an output row that persists until consumed, an attacker who repeatedly sends the AA many small (but above-dust) payments over time can inflate the AA's "unspent output history" indefinitely, and the next time the AA's own logic needs to make a payment, every full node validating that trigger must re-run the same unbounded scan/loop, deterministically, in lock-step with the network.

### Finding Description
`aa_composer.js`'s `sendUnit()` → `completePaymentPayload()` builds `payload.inputs` for an AA-issued payment by calling `readStableOutputs()`: [1](#0-0) 
This query has no `LIMIT` and pulls back every unspent, stable output belonging to the AA's address (and asset) up to the current MCI, ordered deterministically. It then feeds all returned rows into `iterateUnspentOutputs()`: [2](#0-1) 
which loops row-by-row, summing amounts until the target payment amount is reached. If not enough is found among stable outputs, it falls back to `readUnstableOutputsSentByAAs()` (again unbounded, no `LIMIT`) and continues the same accumulation loop: [3](#0-2) [4](#0-3) 

Every payment message sent *to* an AA creates a new row in `outputs` that is only consumed (marked `is_spent=1`) when the AA itself later spends it as an input, exactly analogous to the `_stakingHistoryByToken` array in the report that only grows with each deposit/withdrawal and is fully re-walked on every claim. A dust-threshold check exists (`amount>=FULL_TRANSFER_INPUT_SIZE`, i.e. ≥60 bytes) to block sub-60-byte spam, but nothing bounds the *count* of outputs at or above that threshold that an attacker can create by sending many separate minimal payments to the AA's address. Because AA trigger processing is fully deterministic and re-executed by every full node during unit validation and at stabilization (in `writer.js`/`main_chain.js`), this unbounded SQL fetch + JS accumulation loop is repeated identically by the whole network every time that AA composes a payment, not just once by a single claimant as in the original report.

### Impact Explanation
As the number of small, unconsumed outputs sent to an AA grows (fully attacker-controlled — anyone can pay any AA), the SQL query and subsequent iteration loop that the AA's response-composition logic must execute grows correspondingly. Unlike the reported EVM issue there is no hard gas ceiling, but there is a real, unbounded, deterministic CPU/DB cost imposed on every validating node for a given AA response. In the worst case this can:
- Materially slow down or stall processing/validation of units containing that AA's response, degrading throughput for the whole network segment handling that AA (a form of the "network unable to confirm new units" outcome), and
- Cause the AA's payment composition to effectively never complete in a timely fashion, freezing the AA's own outgoing payments/funds for legitimate users — i.e., an AA fund-freezing condition analogous to the report's "user might never be able to claim rewards."

This differs from the Sherlock report's severity model in that Obyte has no fixed per-unit computational ceiling equivalent to Ethereum's 30M gas block limit for JS-level unit composition (oscript's `MAX_COMPLEXITY`/`MAX_OPS` bound *formula* evaluation, not this database-query-driven composition step), so the "permanently exceeds a hard limit" framing does not translate 1:1. The concrete, provable consequence is a network-wide, attacker-amplifiable performance/availability degradation and AA fund-freezing risk rather than a guaranteed permanent revert.

### Likelihood Explanation
Any unprivileged unit poster can trigger this by repeatedly sending small (≥60-byte) payments to a target AA over an extended period, with no cap on the number of such outputs they can create, and no cost to the attacker beyond ordinary network/transaction fees per payment. The AA itself does not need to cooperate or contain a vulnerability in its own oscript logic — this occurs purely in the platform-level payment composition code (`aa_composer.js`) invoked whenever the AA sends any outgoing base or asset payment. The likelihood of triggering the code path is high; the practical severity depends on how many spam outputs are accumulated, which is entirely at the attacker's discretion and grows linearly with attacker effort over time (identical structural pattern to the original report's "haven't claimed for years, deposited/withdrew every week" scenario).

### Recommendation
- Add a `LIMIT` to `readStableOutputs()`/`readUnstableOutputsSentByAAs()` in `aa_composer.js` and iterate in bounded batches (re-querying only if more inputs are still needed), so the worst-case per-call work is capped.
- Enforce a maximum number of unspent outputs that can accumulate for a single address (or require attacker-supplied dust outputs above a much higher effective bound) similar to how `indivisible_asset.js`'s `pickIndivisibleCoinsForAmount` bounds iterations via `constants.MAX_MESSAGES_PER_UNIT`: [5](#0-4) 
- Consider periodic/automatic consolidation of small outputs belonging to AA addresses, or raising/adaptively tuning the dust threshold (`FULL_TRANSFER_INPUT_SIZE`) based on observed spam patterns, to keep the unspent-output set bounded regardless of attacker activity.

### Proof of Concept
1. Deploy or identify an existing AA that, upon receiving a trigger, sends a `payment` message (any AA with a `messages` block containing an `app: "payment"` output qualifies).
2. As an unprivileged unit poster, repeatedly send the AA many separate payments each just above the dust threshold (`FULL_TRANSFER_INPUT_SIZE`, i.e. slightly more than 60 bytes worth of bytes) over an extended period (e.g., thousands of transactions across weeks/months), never letting the AA's normal activity consume all of them.
3. Trigger the AA to make an outgoing payment that requires accumulating funds via `completePaymentPayload()`.
4. Observe that `readStableOutputs()` (and potentially `readUnstableOutputsSentByAAs()`) must scan and the `iterateUnspentOutputs()` loop must process the full accumulated set of unspent dust outputs before satisfying the target amount, with cost scaling linearly with the number of spam outputs the attacker created — reproducing, at the ocore/AA-composition layer, the unbounded, attacker-amplifiable loop-over-history pattern described in the original report.

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

**File:** aa_composer.js (L1157-1172)
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
```

**File:** aa_composer.js (L1223-1244)
```javascript
			readStableOutputs(function (rows) {
				iterateUnspentOutputs(rows);
				if (bFound && !send_all_output)
					return sortOutputsAndReturn();
				readUnstableOutputsSentByAAs(function (rows2) {
					iterateUnspentOutputs(rows2);
					if (bFound)
						return sortOutputsAndReturn();
					if (!asset)
						return cb('not enough funds for ' + target_amount + ' bytes');
					var bSelfIssueForSendAll = mci < (constants.bTestnet ? 2080483 : constants.aa3UpgradeMci);
					if (!bSelfIssueForSendAll && send_all_output && payload.outputs.length === 1) // send-all is the only output - don't issue for it
						return sortOutputsAndReturn();
					issueAsset(function (err) {
						if (err) {
							console.log("issue failed: " + err);
							return cb('not enough funds for ' + target_amount + ' of asset ' + asset);
						}
						sortOutputsAndReturn();
					});
				});
			});
```

**File:** indivisible_asset.js (L500-505)
```javascript
					accumulated_amount += amount_to_use;
					if (accumulated_amount >= amount - tolerance_minus && accumulated_amount <= amount + tolerance_plus)
						return onDone(null, arrPayloadsWithProofs);
					if (arrPayloadsWithProofs.length >= constants.MAX_MESSAGES_PER_UNIT - 1) // reserve 1 for fees
						return onDone("Too many messages, try sending a smaller amount");
					pickNextCoin(amount - accumulated_amount);
```
